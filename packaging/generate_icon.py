"""Export the existing FL Network cube brand to a multi-size Windows icon.

Build tool only: requires Pillow, never imported by the desktop application.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter


def export_icon():
    size = 768
    scale = size / 96
    def points(coords):
        return [(int(x * scale), int(y * scale)) for x, y in coords]

    canvas = Image.new("RGBA", (size, size))
    mask = Image.new("L", canvas.size)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=23 * scale, fill=255)
    background = Image.new("RGBA", canvas.size)
    draw = ImageDraw.Draw(background)
    for y in range(size):
        ratio = y / (size - 1)
        color = tuple(round(a + (b - a) * ratio) for a, b in zip((20, 39, 70), (8, 13, 27)))
        draw.line((0, y, size, y), fill=color + (255,))
    canvas.paste(background, (0, 0), mask)
    glow = Image.new("RGBA", canvas.size)
    ImageDraw.Draw(glow).polygon(points([(48, 15), (77, 31), (77, 65), (48, 82), (19, 65), (19, 31)]),
                                 outline=(93, 131, 255, 165), width=round(2 * scale))
    canvas = Image.alpha_composite(canvas, glow.filter(ImageFilter.GaussianBlur(3 * scale)))
    faces = [([(48, 17), (76, 33), (48, 49), (20, 33)], (120, 244, 229), (82, 132, 255)),
             ([(20, 33), (20, 64), (48, 80), (48, 49)], (43, 157, 187), (36, 78, 180)),
             ([(76, 33), (76, 64), (48, 80), (48, 49)], (87, 93, 215), (162, 129, 255))]
    for coords, start, end in faces:
        face_mask = Image.new("L", canvas.size)
        ImageDraw.Draw(face_mask).polygon(points(coords), fill=255)
        face = Image.new("RGBA", canvas.size)
        face_draw = ImageDraw.Draw(face)
        for y in range(size):
            ratio = max(0, min(1, (y / scale - 17) / 63))
            color = tuple(round(a + (b - a) * ratio) for a, b in zip(start, end))
            face_draw.line((0, y, size, y), fill=color + (255,))
        canvas.paste(face, (0, 0), face_mask)
    draw = ImageDraw.Draw(canvas)
    for coords in [((48, 17), (76, 33), (76, 64), (48, 80), (20, 64), (20, 33), (48, 17)),
                   ((20, 33), (48, 49), (76, 33)), ((48, 49), (48, 80))]:
        draw.line(points(coords), fill=(180, 251, 242, 195), width=round(1.5 * scale), joint="curve")
    for coords in [((32, 48), (39, 52)), ((32, 57), (39, 61)), ((57, 52), (64, 48)), ((57, 61), (64, 57))]:
        draw.line(points(coords), fill=(210, 245, 255), width=round(2 * scale))
    path = Path(__file__).with_name("fl-network.ico")
    canvas.save(path, format="ICO", sizes=[(n, n) for n in (16, 24, 32, 48, 64, 128, 256)])
    return path


if __name__ == "__main__":
    print(export_icon())
