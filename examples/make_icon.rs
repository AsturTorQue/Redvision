//! Dibuja el icono de RedVisión (red de nodos sobre círculo oscuro) en assets/.
//! Uso: cargo run --example make_icon
use image::{Rgba, RgbaImage};

fn main() {
    let size = 512u32;
    let s = size as f32;
    let mut img = RgbaImage::from_pixel(size, size, Rgba([0, 0, 0, 0]));
    let c = (s / 2.0, s / 2.0);
    let r_out = s * 0.47;
    let ring = s * 0.035;
    // Colores del tema «Medianoche»: violeta sobre morado oscuro.
    let accent = [192.0, 132.0, 252.0];
    let bg = [46.0, 24.0, 84.0];
    let nodes = [(c.0, c.1 - s * 0.2), (c.0 - s * 0.19, c.1 + s * 0.13), (c.0 + s * 0.19, c.1 + s * 0.13)];
    let seg_dist = |px: f32, py: f32, a: (f32, f32), b: (f32, f32)| {
        let (dx, dy) = (b.0 - a.0, b.1 - a.1);
        let t = (((px - a.0) * dx + (py - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
        ((px - a.0 - t * dx).powi(2) + (py - a.1 - t * dy).powi(2)).sqrt()
    };
    for y in 0..size {
        for x in 0..size {
            // 4x4 supermuestreo para bordes suaves
            let mut acc = [0.0f32; 4];
            for sy in 0..4 {
                for sx in 0..4 {
                    let px = x as f32 + (sx as f32 + 0.5) / 4.0;
                    let py = y as f32 + (sy as f32 + 0.5) / 4.0;
                    let d = ((px - c.0).powi(2) + (py - c.1).powi(2)).sqrt();
                    let mut col: Option<[f32; 3]> = None;
                    if d <= r_out {
                        col = Some(if d > r_out - ring { accent } else { bg });
                        let on_line = nodes.iter().any(|n| seg_dist(px, py, (c.0, c.1), *n) < s * 0.022);
                        let on_node = nodes.iter().any(|n| ((px - n.0).powi(2) + (py - n.1).powi(2)).sqrt() < s * 0.07);
                        let on_hub = d < s * 0.05;
                        if on_line || on_node || on_hub {
                            col = Some(accent);
                        }
                    }
                    if let Some(cl) = col {
                        acc[0] += cl[0];
                        acc[1] += cl[1];
                        acc[2] += cl[2];
                        acc[3] += 255.0;
                    }
                }
            }
            if acc[3] > 0.0 {
                let n = acc[3] / 255.0;
                img.put_pixel(x, y, Rgba([(acc[0] / n) as u8, (acc[1] / n) as u8, (acc[2] / n) as u8, (acc[3] / 16.0) as u8]));
            }
        }
    }
    std::fs::create_dir_all("assets").unwrap();
    img.save("assets/icon.png").unwrap();
    let small = image::imageops::resize(&img, 256, 256, image::imageops::FilterType::Lanczos3);
    small.save("assets/icon.ico").unwrap();
    println!("assets/icon.png y assets/icon.ico creados");
}
