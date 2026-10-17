// The page password the editor offers: 20 symbols from 56 that do not read
// alike (no I, O, o, l, 0 or 1), drawn from the OS CSPRNG, about 116 bits with
// no fixed pattern. The recipe is public; the strength is the entropy.
export const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
export const LENGTH = 20;
// Bytes at or above this are dropped, so every symbol is equally likely.
export const LIMIT = 256 - (256 % ALPHABET.length);

// Under this many characters the editor suggests a stronger one.
export const SUGGEST_BELOW = 12;

export function generatePassword(random = (n) => crypto.getRandomValues(new Uint8Array(n))) {
    let out = "";
    while (out.length < LENGTH) {
        for (const b of random(32)) {
            if (b < LIMIT && out.length < LENGTH) out += ALPHABET[b % ALPHABET.length];
        }
    }
    return out;
}
