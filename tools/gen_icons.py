# -*- coding: utf-8 -*-
"""
SwapIP — генератор иконок расширения.

Рисует скруглённый квадрат с диагональным сине-синим градиентом
и двумя белыми стрелками обмена (⇄). Иконки сохраняются в
extension/icons/ (16, 48, 128, 256). Запуск:

    python tools/gen_icons.py
"""

from PIL import Image, ImageDraw
import os

# Цвета фирменного градиента (как кнопка «Подключиться» в popup)
C1 = (59, 130, 246)   # #3b82f6
C2 = (37, 99, 235)    # #2563eb

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extension", "icons")


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient_background(size):
    """Диагональный градиент C1 -> C2."""
    img = Image.new("RGB", (size, size))
    px = img.load()
    denom = 2 * (size - 1) if size > 1 else 1
    for y in range(size):
        for x in range(size):
            px[x, y] = lerp(C1, C2, (x + y) / denom)
    return img


def rounded(img, radius_ratio=0.22):
    """Скругляет углы (прозрачность снаружи)."""
    size = img.size[0]
    r = max(2, round(size * radius_ratio))
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def draw_arrows(img, scale=1.0):
    """Две горизонтальные стрелки: верхняя вправо, нижняя влево."""
    size = img.size[0]
    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)

    u = size / 128.0 * scale  # базовая единица в «пикселях 128-й сетки»

    shaft_h = 14 * u
    head_w = 20 * u
    head_h = 30 * u
    x0 = 22 * u
    x1 = 106 * u
    y_top = 44 * u
    y_bot = 84 * u

    # Верхняя стрелка (вправо): стержень + остриё
    d.rectangle([x0, y_top - shaft_h / 2, x1 - head_w, y_top + shaft_h / 2], fill=white)
    d.polygon(
        [
            (x1 - head_w, y_top - head_h / 2),
            (x1, y_top),
            (x1 - head_w, y_top + head_h / 2),
        ],
        fill=white,
    )

    # Нижняя стрелка (влево)
    d.rectangle([x0 + head_w, y_bot - shaft_h / 2, x1, y_bot + shaft_h / 2], fill=white)
    d.polygon(
        [
            (x0 + head_w, y_bot - head_h / 2),
            (x0, y_bot),
            (x0 + head_w, y_bot + head_h / 2),
        ],
        fill=white,
    )
    return img


def make(size, arrows=True, arrow_scale=1.0):
    img = gradient_background(size)
    img = rounded(img)
    if arrows:
        img = draw_arrows(img.convert("RGBA"), scale=arrow_scale)
    return img


def main():
    os.makedirs(BASE, exist_ok=True)
    # 16 px: стрелки в масштабе слишком мелкие — упрощаем до двух полос
    icon16 = make(16, arrows=False)
    d = ImageDraw.Draw(icon16)
    d.rectangle([2, 5, 11, 7], fill=(255, 255, 255, 255))
    d.polygon([(11, 3), (14, 6), (11, 9)], fill=(255, 255, 255, 255))
    d.rectangle([5, 10, 14, 12], fill=(255, 255, 255, 255))
    d.polygon([(5, 8), (2, 11), (5, 14)], fill=(255, 255, 255, 255))
    icon16.save(os.path.join(BASE, "icon16.png"))

    make(48).save(os.path.join(BASE, "icon48.png"))
    make(128).save(os.path.join(BASE, "icon128.png"))
    make(256, arrow_scale=1.0).save(os.path.join(BASE, "icon256.png"))  # для магазина
    print("Иконки записаны в", os.path.abspath(BASE))


if __name__ == "__main__":
    main()
