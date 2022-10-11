## measuring lines of code of origo

### commands to count:
- for individual folders: `find . -name '*.java' | xargs wc -l`
- or (when file names include special characters such as spaces): `find . -name '*.php' | sed 's/.*/"&"/' | xargs  wc -l`

- for complete repos: `git ls-files | grep '\.js' | xargs wc -l` (only works if you are in a git repo and files have been committed or added with git add)

#### Gadgets

- aes gcm: 115 total
- comparator: 253 total
- helper getIV: 64 total
- shadeco: 269 total
- hkdf: 265 total
- kdc: 198 total

#### Generators

- proxy app generator: 337 total

- deco redactsuffix: 311 total

#### Total Java LoC

- total origo: 115+253+64+269+265+198+337 = 1501

- total deco: 253+269+311 = 833

#### CPP 2PC LoC

- inside deco-oracle/2pc/sh_test/test, measure loc
	100 ./xtabs.cpp
  371 ./prf_server_finished.cpp
  576 ./prf.cpp
   85 ./innerprod.cpp
  290 ./hmac_outer_hash.cpp
   83 ./mult3.cpp
  170 ./hmac_setup.cpp
  371 ./prf_client_finished.cpp
  288 ./hmac_outer_hash_2.cpp
- 2334 total

#### Go lines

- total deco: 22810
- total origo: 22144
- total tls standard lib: 20187

- added lines deco: 2623
- added lines origo: 1957

