pub fn print() {
    let lines = [
        r"   _____                       .__  .__       .__     __   ",
        r"  /     \   ____   ____   ____ |  | |__| ____ |  |___/  |_ ",
        r" /  \ /  \ /  _ \ /  _ \ /    \|  | |  |/ ___\|  |  \   __\",
        r"/    Y    (  <_> |  <_> )   |  \  |_|  / /_/  >   Y  \  |  ",
        r"\____|__  /\____/ \____/|___|  /____/__\___  /|___|  /__|  ",
        r"        \/                   \/       /_____/      \/      ",
    ];
    if std::env::var("NO_COLOR").is_ok() {
        for line in lines {
            println!("{line}");
        }
        return;
    }
    let blue = "\x1b[34m";
    let reset = "\x1b[0m";
    for line in lines {
        println!("{blue}{line}{reset}");
    }
}
