use stream::Encryptor;
use twister::Twister;
use rand;
use time;

pub struct Oracle {
    encryptor: Encryptor,
}

impl Oracle {
    pub fn new() -> Oracle {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let seed = rng.gen();
        println!("Chose seed {}. Shhhh!", seed);
        Oracle { encryptor: Encryptor::new(seed) }
    }

    pub fn write(&mut self, user_controlled: &str) -> Vec<u8> {
        let ciphertext = Oracle::random_prefix().into_iter().chain(
            user_controlled.bytes()
        ).collect::<Vec<u8>>();
        self.encryptor.encrypt(&ciphertext[..])
    }

    fn random_prefix() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let len = rng.gen::<u8>() as usize;
        let mut prefix = Vec::with_capacity(len);
        for _ in 0..len {
            prefix.push(rng.gen());
        }
        prefix
    }
}

pub struct PasswordToken{
    token: u32,
}

impl PasswordToken {
    pub fn from_time() -> PasswordToken {
        let seed = time::get_time().sec as u32;
        PasswordToken{ token: Twister::new(seed).next().unwrap() }
    }

    pub fn random() -> PasswordToken {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let seed = rng.gen();
        PasswordToken{ token: Twister::new(seed).next().unwrap() }
    }

    pub fn token(&self) -> u32 {
        self.token
    }
}
