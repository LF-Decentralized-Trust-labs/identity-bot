package agenthost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"image"
	"image/jpeg"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"identity-agent-core/screenview"
)

// A body's screen, shown to the people allowed to watch it.
//
// The body says on its sealed connection to the Identity Agent what screen it
// has, and waits there to be watched. While somebody is watching, it looks at
// the screen a few times a second and sends a picture whenever it changed; when
// nobody has fetched a picture for a few seconds the Identity Agent tells it to
// stop, and it goes back to waiting. A person who took control sends clicks
// and keys back the same way, which the body passes to its screen.

// Screen is a machine's screen, as a body sees and drives it.
type Screen interface {
	// Describe says how large the screen is and whether it can take clicks
	// and keys.
	Describe() (screenview.Screen, error)
	// Capture is what the screen shows now.
	Capture() (*image.RGBA, error)
	// Apply does what a person did, with its coordinates on the screen itself.
	Apply(screenview.Event) error
	// Release lets go of every button and key Apply left held down: called
	// when control is given back and when nobody is watching any more.
	Release() error
	Close() error
}

// ErrNoScreen is a machine with no screen this body can show.
var ErrNoScreen = errors.New("this machine has no screen this program can show")

// ErrScreenNotYet is a Mac or a Windows computer, whose screen this program
// cannot read or drive yet. It is ErrNoScreen, saying why in the words the
// app uses too.
var ErrScreenNotYet = fmt.Errorf("%w: %s", ErrNoScreen, screenview.NotYetSentence)

// ErrNetworkDisplay is an X display on another machine, asked for without
// --display-allow-network.
var ErrNetworkDisplay = errors.New("the display is on another machine, reached over the network")

// isNetworkDisplay says an X display name reaches a display over the network:
// "host:0" or "host/tcp:0", rather than ":0", "unix:0" or a socket's path.
func isNetworkDisplay(display string) bool {
	if strings.HasPrefix(display, "/") {
		return false
	}
	colon := strings.LastIndex(display, ":")
	if colon < 0 {
		return false
	}
	host := display[:colon]
	if i := strings.Index(host, "/"); i >= 0 {
		// "host/protocol": only a Unix socket stays on this machine.
		return host[i+1:] != "unix"
	}
	return host != "" && host != "unix"
}

// checkDisplay refuses an X display reached over the network unless it was
// asked for. The X protocol over a network is not encrypted and not
// authenticated beyond a cookie sent in the clear: anyone on the way sees
// every picture of the screen and every key typed, and can type their own.
// When it is allowed, it is said, every time.
func checkDisplay(display string, allowNetwork bool) error {
	if !isNetworkDisplay(display) {
		return nil
	}
	if !allowNetwork {
		return fmt.Errorf("%w: %s. The screen and every key would cross the network unencrypted, "+
			"so it is not offered; run agent-host on the machine with the display, or give "+
			"--display-allow-network to accept that", ErrNetworkDisplay, display)
	}
	fmt.Fprintf(os.Stderr, "agent-host: warning: the display %s is on another machine. Its pictures and every "+
		"click and key cross the network unencrypted, readable and changeable by anyone on the way.\n", display)
	return nil
}

// ScreenMode says what a body lets people do with its screen.
type ScreenMode string

const (
	// ScreenOff shows nothing: the body says it has no screen.
	ScreenOff ScreenMode = "off"
	// ScreenWatch shows the screen and refuses clicks and keys.
	ScreenWatch ScreenMode = "watch"
	// ScreenControl shows the screen and passes on clicks and keys from a
	// person the Identity Agent let take control.
	ScreenControl ScreenMode = "control"
)

// ParseScreenMode reads a mode as a person types it.
func ParseScreenMode(s string) (ScreenMode, error) {
	switch m := ScreenMode(s); m {
	case ScreenOff, ScreenWatch, ScreenControl:
		return m, nil
	case "":
		return ScreenControl, nil
	}
	return "", fmt.Errorf("--screen is off, watch or control, not %q", s)
}

// maxPictureWidth bounds the width of a picture as sent. A wider screen is
// shrunk, which keeps a picture small enough to send several times a second.
const maxPictureWidth = 1280

// pictureQuality is the JPEG quality pictures are sent at.
const pictureQuality = 60

// quietPost is how often a body says "unchanged" when nothing changed and
// nobody is in control: often enough that the Identity Agent knows it is still
// there, rarely enough to cost nothing.
const quietPost = time.Second

// ShowScreen is the body offering its screen, until ctx ends. A screen of nil
// tells the Identity Agent this machine has none, so nobody is offered a
// button that cannot work.
func (h *Host) ShowScreen(ctx context.Context, scr Screen, mode ScreenMode, logger *log.Logger) {
	logf := log.Printf
	if logger != nil {
		logf = logger.Printf
	}
	backoff := time.Second
	for ctx.Err() == nil {
		var desc *screenview.Screen
		if scr != nil && mode != ScreenOff {
			d, err := scr.Describe()
			if err != nil {
				logf("[agent-host] the screen cannot be read (%v); saying there is none", err)
			} else {
				d.CanControl = d.CanControl && mode == ScreenControl
				desc = &d
			}
		}
		body, _ := json.Marshal(map[string]any{"screen": desc})
		code, b, err := h.CallContext(ctx, "POST", "/api/agent-host/screen", body)
		var answer struct {
			Watch bool `json:"watch"`
			FPS   int  `json:"fps"`
		}
		if err == nil && code == http.StatusOK {
			err = json.Unmarshal(b, &answer)
		} else if err == nil {
			err = fmt.Errorf("the Identity Agent answered %d: %s", code, b)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait := backoff + time.Duration(rand.Int63n(int64(backoff/2)+1))
			logf("[agent-host] could not offer the screen (%v); trying again in %s", err, wait.Round(time.Second))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			if backoff *= 2; backoff > time.Minute {
				backoff = time.Minute
			}
			continue
		}
		backoff = time.Second
		if desc == nil {
			// Nothing to show: say so again before the word runs out.
			select {
			case <-time.After(screenview.AdvertisedFor / 2):
			case <-ctx.Done():
				return
			}
			continue
		}
		if answer.Watch {
			logf("[agent-host] somebody is watching the screen")
			if err := h.streamScreen(ctx, scr, mode, answer.FPS); err != nil && ctx.Err() == nil {
				logf("[agent-host] stopped showing the screen: %v", err)
			} else {
				logf("[agent-host] nobody is watching the screen any more")
			}
		}
	}
}

// streamScreen sends pictures until the Identity Agent says nobody is
// watching.
func (h *Host) streamScreen(ctx context.Context, scr Screen, mode ScreenMode, fps int) error {
	if fps <= 0 || fps > 10 {
		fps = screenview.FramesPerSecond
	}
	tick := time.NewTicker(time.Second / time.Duration(fps))
	defer tick.Stop()
	var last uint64
	var lastPost time.Time
	control := false
	// Nothing is left held down once this stops: a drag or a shortcut cut off
	// by the viewer leaving would otherwise stay pressed on the machine.
	defer func() { _ = scr.Release() }()
	for {
		img, err := scr.Capture()
		if err != nil {
			return fmt.Errorf("the screen cannot be read: %w", err)
		}
		pic := shrink(img, maxPictureWidth)
		sum := fnv.New64a()
		_, _ = sum.Write(pic.Pix)
		changed := sum.Sum64() != last
		if changed || control || time.Since(lastPost) >= quietPost {
			req := map[string]any{"width": pic.Rect.Dx(), "height": pic.Rect.Dy()}
			if changed {
				var buf bytes.Buffer
				if err := jpeg.Encode(&buf, pic, &jpeg.Options{Quality: pictureQuality}); err != nil {
					return err
				}
				req["image"] = base64.StdEncoding.EncodeToString(buf.Bytes())
			}
			body, _ := json.Marshal(req)
			code, b, err := h.CallContext(ctx, "POST", "/api/agent-host/screen/frame", body)
			if err != nil {
				return err
			}
			if code != http.StatusOK {
				return fmt.Errorf("the Identity Agent answered %d: %s", code, b)
			}
			var got struct {
				KeepGoing bool               `json:"keep_going"`
				Control   bool               `json:"control"`
				Events    []screenview.Event `json:"events"`
			}
			if err := json.Unmarshal(b, &got); err != nil {
				return err
			}
			if !got.KeepGoing {
				return nil
			}
			if changed {
				last = sum.Sum64()
			}
			lastPost = time.Now()
			wasControl := control
			control = got.Control && mode == ScreenControl
			if wasControl && !control {
				if err := scr.Release(); err != nil {
					log.Printf("[agent-host] could not let go of what was held down: %v", err)
				}
			}
			if len(got.Events) > 0 {
				if mode != ScreenControl {
					log.Printf("[agent-host] ignored %d clicks and keys: this machine shows its screen but does not take control", len(got.Events))
				} else {
					applyEvents(scr, got.Events, img.Rect.Dx(), img.Rect.Dy(), pic.Rect.Dx(), pic.Rect.Dy())
				}
			}
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// applyEvents does what a person did, each event checked again here against
// the picture they saw and moved from its coordinates to the screen's.
func applyEvents(scr Screen, events []screenview.Event, screenW, screenH, picW, picH int) {
	for _, e := range events {
		if err := e.Check(picW, picH); err != nil {
			log.Printf("[agent-host] ignored a click or key: %v", err)
			continue
		}
		e.X = e.X * screenW / picW
		e.Y = e.Y * screenH / picH
		if err := scr.Apply(e); err != nil {
			log.Printf("[agent-host] could not pass on a click or key: %v", err)
		}
	}
}

// shrink is img at most maxW wide, keeping its shape.
func shrink(img *image.RGBA, maxW int) *image.RGBA {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	if w <= maxW {
		return img
	}
	nw, nh := maxW, h*maxW/w
	if nh < 1 {
		nh = 1
	}
	out := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy := img.Rect.Min.Y + y*h/nh
		for x := 0; x < nw; x++ {
			sx := img.Rect.Min.X + x*w/nw
			si := img.PixOffset(sx, sy)
			di := out.PixOffset(x, y)
			copy(out.Pix[di:di+4], img.Pix[si:si+4])
		}
	}
	return out
}
