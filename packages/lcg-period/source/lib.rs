fn lcg_next(m: u64, a: u64, c: u64, x: u64) -> u64 {
    (a * x + c) % m
}

#[no_mangle]
// Floyd's cycle-finding algorithm, aka the "tortoise and the hare" algorithm
pub extern "C" fn lcg_period(m: u64, a: u64, c: u64, x: u64) -> u64 {
    let mut tortoise = lcg_next(m, a, c, x);
    let mut hare = lcg_next(m, a, c, lcg_next(m, a, c, x));

    // Phase 1: Find a repetition x_i = x_2i
    while tortoise != hare {
        tortoise = lcg_next(m, a, c, tortoise);
        hare = lcg_next(m, a, c, lcg_next(m, a, c, hare));
    }

    // Phase 2: Find the position μ of first repetition
    hare = x;
    while tortoise != hare {
        tortoise = lcg_next(m, a, c, tortoise);
        hare = lcg_next(m, a, c, hare);
    }

    // Phase 3: Find the length λ of the shortest cycle
    let mut lambda = 1;
    hare = lcg_next(m, a, c, tortoise);
    while hare != tortoise {
        hare = lcg_next(m, a, c, hare);
        lambda += 1;
    }

    lambda
}
