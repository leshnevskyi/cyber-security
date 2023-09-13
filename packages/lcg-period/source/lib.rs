#[no_mangle]
pub extern "C" fn lcg_period(m: u64, a: u64, c: u64, seed: u64) -> u64 {
    let mut tortoise = (a * seed + c) % m; // Tortoise's first move
    let mut hare = (a * (a * seed + c) + c) % m; // Hare's first two moves

    // Phase 1: Detect a cycle
    while tortoise != hare {
        tortoise = (a * tortoise + c) % m;
        hare = (a * (a * hare + c) + c) % m;
    }

    // Phase 2: Find the start of the cycle
    hare = seed;
    while tortoise != hare {
        tortoise = (a * tortoise + c) % m;
        hare = (a * hare + c) % m;
    }

    // Phase 3: Determine the cycle length
    let mut length = 1;
    hare = (a * tortoise + c) % m;
    while tortoise != hare {
        hare = (a * hare + c) % m;
        length += 1;
    }

    length
}
