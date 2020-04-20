# BLS Ordering test

I wanted to know if it matter to use the curve modulus or the curve order parameter when computing
BLS signatures. This test shows it doesn't matter but operations done with the curve modulus yields
better entropy. Can't find a reason why one would use the curve order vs the curve modulus but I'm not a cryptographer.

## To run 

`cargo run`

## Install rust

`curl https://sh.rustup.rs -sSf | sh -s -- -y`