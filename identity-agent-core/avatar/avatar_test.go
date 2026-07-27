package avatar

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func decode(t *testing.T, dataURI string) image.Image {
	t.Helper()
	raw, err := DecodeDataURI(dataURI)
	if err != nil {
		t.Fatalf("decode data URI: %v", err)
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode image: %v", err)
	}
	return img
}

// photo builds a source image with real gradients and an edge, so the filter
// tests are exercising something rather than a flat field.
func photo(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{uint8(x * 255 / w), uint8(y * 255 / h), 128, 255}
			if x > w/2 {
				c = color.RGBA{20, 20, 20, 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}

// The guarantee the whole design rests on: asking for an avatar always gets
// one, with no input and no network.
func TestGenerateAlwaysProducesAnImage(t *testing.T) {
	got, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(got, "data:image/") {
		t.Fatalf("not a data URI: %.32q", got)
	}
	img := decode(t, got)
	if img.Bounds().Dx() != Size || img.Bounds().Dy() != Size {
		t.Errorf("generated %dx%d, want %dx%d", img.Bounds().Dx(), img.Bounds().Dy(), Size, Size)
	}
}

// It is decoration, not an identifier, so it must not be derived from anything
// and must not repeat.
func TestGeneratedAvatarsDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		got, err := Generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[got] {
			t.Fatal("two generated avatars were identical — this must not be an identifier")
		}
		seen[got] = true
	}
}

// A generated avatar is flat colour, so it should stay small enough that
// nobody thinks twice about it travelling inside an introduction.
func TestGeneratedAvatarIsSmall(t *testing.T) {
	got, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, _ := DecodeDataURI(got)
	if len(raw) > 4096 {
		t.Errorf("generated avatar is %d bytes — expected under 4KB for flat art", len(raw))
	}
}

// Whatever the user picks comes out the same shape and size as everyone
// else's, so no screen has to cope with a surprise.
func TestNormalizeSquaresAndScales(t *testing.T) {
	for _, dims := range [][2]int{{800, 400}, {400, 900}, {50, 50}, {1024, 1024}} {
		got, err := Normalize(photo(t, dims[0], dims[1]))
		if err != nil {
			t.Fatalf("normalize %v: %v", dims, err)
		}
		img := decode(t, got)
		if img.Bounds().Dx() != Size || img.Bounds().Dy() != Size {
			t.Errorf("source %v normalized to %dx%d, want %dx%d",
				dims, img.Bounds().Dx(), img.Bounds().Dy(), Size, Size)
		}
	}
}

// A photo at avatar size should land in single-digit kilobytes — small enough
// that carrying it is never a consideration.
func TestNormalizedPhotoIsSmall(t *testing.T) {
	got, err := Normalize(photo(t, 1600, 1200))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	raw, _ := DecodeDataURI(got)
	if len(raw) > 12000 {
		t.Errorf("normalized photo is %d bytes — expected well under 12KB at %dpx", len(raw), Size)
	}
}

func TestNormalizeRejectsNonImages(t *testing.T) {
	if _, err := Normalize([]byte("this is not an image")); err == nil {
		t.Error("garbage was accepted as an image")
	}
}

// The cartoon filter has to actually change the picture — flattening colour
// and drawing edges — or the feature is a no-op that looks like it works.
func TestStylizeFlattensColourAndDrawsEdges(t *testing.T) {
	src := photo(t, 400, 400)

	plain, err := Normalize(src)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	drawn, err := Stylize(src)
	if err != nil {
		t.Fatalf("stylize: %v", err)
	}
	if plain == drawn {
		t.Fatal("stylize returned the original — no filter was applied")
	}

	stylized := decode(t, drawn)
	if stylized.Bounds().Dx() != Size {
		t.Errorf("stylized to %dpx, want %d", stylized.Bounds().Dx(), Size)
	}

	// Flattening means fewer distinct colours than the photograph had.
	if a, b := distinctColours(decode(t, plain)), distinctColours(stylized); b >= a {
		t.Errorf("stylized image has %d distinct colours vs %d in the photo — colour was not flattened", b, a)
	}
	// And the hard vertical edge in the fixture should be drawn in.
	if !hasDarkOutline(stylized) {
		t.Error("no outline was drawn over the flattened colour")
	}
}

func TestStylizeRejectsNonImages(t *testing.T) {
	if _, err := Stylize([]byte("still not an image")); err == nil {
		t.Error("garbage was accepted for stylizing")
	}
}

// A data URI we produced must survive a round trip, and a client that sends
// bare base64 must still work.
func TestDataURIRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatalf("encode: %v", err)
	}
	uri := DataURI("image/png", buf.Bytes())
	back, err := DecodeDataURI(uri)
	if err != nil || !bytes.Equal(back, buf.Bytes()) {
		t.Fatalf("round trip failed: %v", err)
	}
	bare, err := DecodeDataURI(strings.SplitN(uri, ";base64,", 2)[1])
	if err != nil || !bytes.Equal(bare, buf.Bytes()) {
		t.Fatalf("bare base64 was rejected: %v", err)
	}
	if _, err := DecodeDataURI("!!!not base64!!!"); err == nil {
		t.Error("garbage decoded as base64")
	}
}

func distinctColours(img image.Image) int {
	seen := map[color.RGBA]bool{}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			seen[color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(bl >> 8), 255}] = true
		}
	}
	return len(seen)
}

func hasDarkOutline(img image.Image) bool {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			if r>>8 < 40 && g>>8 < 40 && bl>>8 < 40 {
				return true
			}
		}
	}
	return false
}
