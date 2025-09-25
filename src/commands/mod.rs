use crate::cli::RegistryImage;

pub fn run_image(image_name: String) {
    let parsed_image = RegistryImage::parse(&image_name).unwrap();
    if parsed_image.registry == None {
        println!("Registry is empty defaulting to docker.io");
        let registry: &str = "docker.io";
        println!("Registry: {registry}");
    } else {
        println!("Registry: {:?}", parsed_image.registry);
    }

    println!("Image: {:?}", parsed_image.image);
    println!("Tag: {:?}", parsed_image.tag);
}

