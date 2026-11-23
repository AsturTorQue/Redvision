// En Windows incrusta el icono y los datos de versión en el .exe.
fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "RedVisión");
        res.set("FileDescription", "RedVisión - Analizador de red");
        if let Err(e) = res.compile() {
            println!("cargo:warning=No se pudo incrustar el icono: {}", e);
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
