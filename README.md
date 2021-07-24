# Generate N random, unique 256 bit numbers.

Utility to generate a random list of unpredictable 256 bit numbers; which are guaranteed
unique.

## syntax

    Syntax resign [-r /dev/random] N
    
      -r      Random device; expects /dev/urandom or the type of output of a hardware random generator.
              can be repeated. Default is /dev/urandom. Use '-' for stdin.

      N       Number of keys to generate.

The numbers will be output as back to back binary stream.

# Hardware random generators

Tested against

 * Infinite Noise TRNG  (https://www.crowdsupply.com/13-37/infinite-noise-trng), https://www.tindie.com/products/manueldomke/infinite-noise-trng-true-random-number-generator/
 * nCipher HSM
 * TrueRNG V3 - USB Hardware Random Number Generator
 * https://onerng.info/
 * http://www.jtxp.org/tech/xr232usb_en.htm
 * Quantis QRNG legacy (FreeBSD)


