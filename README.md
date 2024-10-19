# The Settlers II 10th Anniversary and RoC/AdK decrypter/encrypter

decrypts and encrypts the assets of The Settlers II 10th Anniversary.

## How To Build

Have cargo installed and run `cargo run /path/to/file/or/dir`

_Note: you need at least c++ 17 to be able to compile it_

## Ussage

### Windows

On widows you can drag and drop the files you want to decrypt/encrypt onto the exe. this works with single files, multiple files, and even folders. The program decrypts the files depending on the file header this mechanism also detects if the file is from 10th Anniversary or from AdK. It saves the file with a .dng or .adk extention (befor the actual extention, so programs can still assosiate themselves with the file).
If you want to encrypt a file it needs to have the .dng or .adk extention so the program know for which game it should encode the file. The encrypted file gets saved to the place with the the original encrypted file was (aka the extention gets removed).

_Note: if you installed the game in the default folder the program won't be able to save the decrypted file in that location because it doesn't have sufficient rights_

## Troubleshooting

If it doesn't work for you:

1. maybe it doesn't have permission to create a file in that location; try copying what you want to decrypt to your desktop and try again.
2. try using it with cmd to see the error log.
