// Package avatar gives every identity a face.
//
// An avatar is always present. That is the whole design: a profile without a
// picture forces every screen, every introduction and every contact list to
// carry a "what if there is nothing" branch, and those branches are where
// silent behaviour hides — the fallback that quietly fetches an image from
// somewhere it should not.
//
// So one is generated at identity creation, on the device, with no network and
// no service. The user can replace it with a photo, or with a cartooned
// version of that photo, or with any image at all. It does not have to be
// their face, it is not an identity claim, and nothing verifies it. Proving who
// somebody is happens with credentials, not with a picture.
package avatar

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"math"
	"strings"

	_ "image/gif" // decode support for whatever the user picks
)

// Size is the stored edge length in pixels. Small enough to sit in a profile
// record and travel inside an introduction without thought, large enough to
// look right on a high-density screen at the sizes we render it.
const Size = 100

// jpegQuality is used for photographs. Generated art is flat colour and goes
// out as PNG, which is both smaller and lossless for that content.
const jpegQuality = 82

// MaxSourceBytes caps what we will decode from a caller. A camera original is
// well under this; anything larger is a mistake or an attack.
const MaxSourceBytes = 12 << 20

// DataURI wraps encoded image bytes for storage in the profile record, which
// holds a string.
func DataURI(mime string, raw []byte) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(raw)
}

// DecodeDataURI unwraps what DataURI produced. It also accepts bare base64, so
// a client that sends unwrapped bytes still works.
func DecodeDataURI(s string) ([]byte, error) {
	if i := strings.Index(s, ";base64,"); i >= 0 {
		s = s[i+len(";base64,"):]
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("avatar is not valid base64: %w", err)
	}
	if len(raw) > MaxSourceBytes {
		return nil, fmt.Errorf("image is larger than %d bytes", MaxSourceBytes)
	}
	return raw, nil
}

// Generate produces a fresh avatar with no input from the user and no network.
// Two calls give two different results: this is decoration, not an identifier,
// so there is nothing to derive it from and nothing to keep stable.
func Generate() (string, error) {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("generate avatar: %w", err)
	}
	img := paint(seed)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return DataURI("image/png", buf.Bytes()), nil
}

// Normalize takes whatever the user chose — a photo, a drawing, a cat — and
// returns it centre-cropped to a square and scaled to Size, so every avatar in
// the system is the same shape and roughly the same weight.
func Normalize(raw []byte) (string, error) {
	src, format, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("could not read that image: %w", err)
	}
	out := scale(cropSquare(src), Size)
	return encode(out, format)
}

// Stylize turns a photograph into a drawing of itself, on the device, with no
// model and no network.
//
// It is the classic two-step: flatten the colours into bands, then lay the
// detected edges back over them as dark lines. That is enough to read as an
// illustration at avatar size, and it means the honest version of the promise —
// your photo never leaves your phone — costs no download and no inference.
func Stylize(raw []byte) (string, error) {
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("could not read that image: %w", err)
	}
	small := scale(cropSquare(src), Size)
	drawn := cartoon(small)
	var buf bytes.Buffer
	if err := png.Encode(&buf, drawn); err != nil {
		return "", err
	}
	return DataURI("image/png", buf.Bytes()), nil
}

// --- generation ---

func paint(seed []byte) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, Size, Size))
	bg, fg := colorsFromSeed(seed)
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)

	// A small symmetric pattern: fill a half-grid from the seed bits and mirror
	// it. Symmetry is what makes the result read as a deliberate mark rather
	// than noise, and it costs nothing.
	const cells = 5
	cell := Size / cells
	for y := 0; y < cells; y++ {
		for x := 0; x <= cells/2; x++ {
			bit := seed[(y*cells+x)%len(seed)] >> uint((x+y)%7) & 1
			if bit == 0 {
				continue
			}
			for _, cx := range []int{x, cells - 1 - x} {
				rect := image.Rect(cx*cell, y*cell, (cx+1)*cell, (y+1)*cell)
				draw.Draw(img, rect, &image.Uniform{fg}, image.Point{}, draw.Src)
			}
		}
	}
	return img
}

// colorsFromSeed picks a background and a foreground that contrast enough to
// read at a glance.
func colorsFromSeed(seed []byte) (bg, fg color.RGBA) {
	hue := float64(seed[0]) / 255 * 360
	bg = fromHSL(hue, 0.55, 0.86)
	fg = fromHSL(hue, 0.62, 0.38)
	return bg, fg
}

func fromHSL(h, s, l float64) color.RGBA {
	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2
	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return color.RGBA{
		R: clamp8((r + m) * 255),
		G: clamp8((g + m) * 255),
		B: clamp8((b + m) * 255),
		A: 255,
	}
}

// --- image plumbing ---

// cropSquare takes the largest centred square, so a portrait keeps the face
// rather than the ceiling.
func cropSquare(src image.Image) image.Image {
	b := src.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	offX := b.Min.X + (b.Dx()-side)/2
	offY := b.Min.Y + (b.Dy()-side)/2
	out := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(out, out.Bounds(), src, image.Point{offX, offY}, draw.Src)
	return out
}

// scale resamples to size x size with bilinear interpolation — enough for a
// downscale to 100 pixels, and it keeps the package dependency-free.
func scale(src image.Image, size int) *image.RGBA {
	b := src.Bounds()
	out := image.NewRGBA(image.Rect(0, 0, size, size))
	if b.Dx() == 0 || b.Dy() == 0 {
		return out
	}
	xRatio := float64(b.Dx()) / float64(size)
	yRatio := float64(b.Dy()) / float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			sx := float64(x)*xRatio + float64(b.Min.X)
			sy := float64(y)*yRatio + float64(b.Min.Y)
			out.Set(x, y, bilinear(src, sx, sy))
		}
	}
	return out
}

func bilinear(src image.Image, x, y float64) color.RGBA {
	b := src.Bounds()
	x0, y0 := int(x), int(y)
	x1, y1 := min(x0+1, b.Max.X-1), min(y0+1, b.Max.Y-1)
	fx, fy := x-float64(x0), y-float64(y0)

	c00 := at(src, x0, y0)
	c10 := at(src, x1, y0)
	c01 := at(src, x0, y1)
	c11 := at(src, x1, y1)

	lerp := func(a, b float64, t float64) float64 { return a + (b-a)*t }
	mix := func(a, b, c, d uint8) uint8 {
		top := lerp(float64(a), float64(b), fx)
		bot := lerp(float64(c), float64(d), fx)
		return clamp8(lerp(top, bot, fy))
	}
	return color.RGBA{
		R: mix(c00.R, c10.R, c01.R, c11.R),
		G: mix(c00.G, c10.G, c01.G, c11.G),
		B: mix(c00.B, c10.B, c01.B, c11.B),
		A: 255,
	}
}

func at(src image.Image, x, y int) color.RGBA {
	r, g, b, _ := src.At(x, y).RGBA()
	return color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), 255}
}

// encode writes a photograph as JPEG and anything else as PNG. Flat art keeps
// its clean edges; a photograph does not pay for detail it does not have.
func encode(img image.Image, sourceFormat string) (string, error) {
	var buf bytes.Buffer
	if sourceFormat == "jpeg" {
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			return "", err
		}
		return DataURI("image/jpeg", buf.Bytes()), nil
	}
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return DataURI("image/png", buf.Bytes()), nil
}

// --- the cartoon filter ---

// cartoon flattens colour into bands and draws the edges back on top.
func cartoon(src *image.RGBA) *image.RGBA {
	b := src.Bounds()
	out := image.NewRGBA(b)

	// 1. Quantise. Rounding each channel to a small number of steps is what
	//    turns continuous shading into the flat areas that read as drawn.
	const levels = 6
	step := 255.0 / float64(levels-1)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := at(src, x, y)
			out.SetRGBA(x, y, color.RGBA{
				R: clamp8(math.Round(float64(c.R)/step) * step),
				G: clamp8(math.Round(float64(c.G)/step) * step),
				B: clamp8(math.Round(float64(c.B)/step) * step),
				A: 255,
			})
		}
	}

	// 2. Outline. A Sobel gradient over the luminance of the original, laid
	//    back over the flattened colour wherever the gradient is strong.
	const edgeThreshold = 52.0
	for y := b.Min.Y + 1; y < b.Max.Y-1; y++ {
		for x := b.Min.X + 1; x < b.Max.X-1; x++ {
			if sobel(src, x, y) > edgeThreshold {
				out.SetRGBA(x, y, color.RGBA{0x1A, 0x1A, 0x1A, 0xFF})
			}
		}
	}
	return out
}

func sobel(src *image.RGBA, x, y int) float64 {
	var gx, gy float64
	kernelX := [3][3]float64{{-1, 0, 1}, {-2, 0, 2}, {-1, 0, 1}}
	kernelY := [3][3]float64{{-1, -2, -1}, {0, 0, 0}, {1, 2, 1}}
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			l := luminance(at(src, x+dx, y+dy))
			gx += l * kernelX[dy+1][dx+1]
			gy += l * kernelY[dy+1][dx+1]
		}
	}
	return math.Hypot(gx, gy)
}

func luminance(c color.RGBA) float64 {
	return 0.299*float64(c.R) + 0.587*float64(c.G) + 0.114*float64(c.B)
}

func clamp8(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(v)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
