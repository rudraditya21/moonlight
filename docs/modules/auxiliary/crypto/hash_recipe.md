# `auxiliary/crypto/hash_recipe`

## Purpose
`hash_recipe` computes and verifies composable hash expressions (nested hash chains, salts, UTF-16LE transforms, binary intermediate digests).

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `RECIPE` | `string` | yes | - | Recipe expression to execute |
| `PASS` | `string` | no | - | Password input (`$pass`) |
| `SALT` | `string` | no | - | Salt input (`$salt`) |
| `SALT1` | `string` | no | - | Salt input 1 (`$salt1`) |
| `SALT2` | `string` | no | - | Salt input 2 (`$salt2`) |
| `USERNAME` | `string` | no | - | Username input (`$username`) |
| `CX` | `string` | no | - | Custom token input (`$cx` or `CX`) |
| `HASH` | `string` | no | - | Expected value for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Hex-encode raw byte outputs |

## Supported Functions
- `md5`
- `sha1`
- `sha224`
- `sha256`
- `sha384`
- `sha512`
- `sha256_bin`
- `sha512_bin`
- `blake2b-256` / `blake2b_256`
- `blake2b-512` / `blake2b_512`
- `utf16le`
- `strtoupper`

## Expression Rules
- Concatenate with `.` (dot): `md5($pass.$salt)`
- Nest function calls: `sha256($salt.sha256_bin($pass))`
- Use variables with `$`: `$pass`, `$salt`, `$salt1`, `$salt2`, `$username`, `$cx`
- String literal support: `':'`

## Recipe Catalog (80)
1. `md5(utf16le($pass))`
2. `sha1(utf16le($pass))`
3. `sha256(utf16le($pass))`
4. `sha384(utf16le($pass))`
5. `sha512(utf16le($pass))`
6. `BLAKE2b-256($pass.$salt)`
7. `BLAKE2b-256($salt.$pass)`
8. `BLAKE2b-512($pass.$salt)`
9. `BLAKE2b-512($salt.$pass)`
10. `md5($pass.$salt)`
11. `md5($salt.$pass)`
12. `md5($salt.$pass.$salt)`
13. `md5($salt.md5($pass))`
14. `md5($salt.md5($pass).$salt)`
15. `md5($salt.md5($pass.$salt))`
16. `md5($salt.md5($salt.$pass))`
17. `md5($salt.sha1($salt.$pass))`
18. `md5($salt.utf16le($pass))`
19. `md5($salt1.$pass.$salt2)`
20. `md5($salt1.sha1($salt2.$pass))`
21. `md5($salt1.strtoupper(md5($salt2.$pass)))`
22. `md5(md5($pass))`
23. `md5(md5($pass).md5($salt))`
24. `md5(md5($pass.$salt))`
25. `md5(md5($salt).md5(md5($pass)))`
26. `md5(md5(md5($pass)))`
27. `md5(md5(md5($pass)).$salt)`
28. `md5(md5(md5($pass).$salt1).$salt2)`
29. `md5(md5(md5($pass.$salt1)).$salt2)`
30. `md5(sha1($pass))`
31. `md5(sha1($pass).$salt)`
32. `md5(sha1($pass).md5($pass).sha1($pass))`
33. `md5(sha1($pass.$salt))`
34. `md5(sha1($salt).md5($pass))`
35. `md5(sha1($salt.$pass))`
36. `md5(sha1(md5($pass)))`
37. `md5(strtoupper(md5($pass)))`
38. `md5(utf16le($pass).$salt)`
39. `sha1($pass.$salt)`
40. `sha1($salt.$pass)`
41. `sha1($salt.$pass.$salt)`
42. `sha1($salt.sha1($pass))`
43. `sha1($salt.sha1($pass.$salt))`
44. `sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))`
45. `sha1($salt.utf16le($pass))`
46. `sha1($salt1.$pass.$salt2)`
47. `sha1(CX)`
48. `sha1(md5($pass))`
49. `sha1(md5($pass).$salt)`
50. `sha1(md5($pass.$salt))`
51. `sha1(md5(md5($pass)))`
52. `sha1(sha1($pass))`
53. `sha1(sha1($pass).$salt)`
54. `sha1(sha1($salt.$pass.$salt))`
55. `sha1(utf16le($pass).$salt)`
56. `sha224($pass.$salt)`
57. `sha224($salt.$pass)`
58. `sha224(sha1($pass))`
59. `sha224(sha224($pass))`
60. `sha256($pass.$salt)`
61. `sha256($salt.$pass)`
62. `sha256($salt.$pass.$salt)`
63. `sha256($salt.sha256($pass))`
64. `sha256($salt.sha256_bin($pass))`
65. `sha256($salt.utf16le($pass))`
66. `sha256(md5($pass))`
67. `sha256(sha256($pass).$salt)`
68. `sha256(sha256($pass.$salt))`
69. `sha256(sha256_bin($pass))`
70. `sha256(utf16le($pass).$salt)`
71. `sha384($pass.$salt)`
72. `sha384($salt.$pass)`
73. `sha384($salt.utf16le($pass))`
74. `sha384(utf16le($pass).$salt)`
75. `sha512($pass.$salt)`
76. `sha512($salt.$pass)`
77. `sha512($salt.utf16le($pass))`
78. `sha512(sha512($pass).$salt)`
79. `sha512(sha512_bin($pass).$salt)`
80. `sha512(utf16le($pass).$salt)`

## Example
```text
moonlight> use auxiliary/crypto/hash_recipe
moonlight(auxiliary/crypto/hash_recipe)> set RECIPE sha256($salt.sha256_bin($pass))
moonlight(auxiliary/crypto/hash_recipe)> set PASS P@ssw0rd!
moonlight(auxiliary/crypto/hash_recipe)> set SALT NaCl
moonlight(auxiliary/crypto/hash_recipe)> run
```

## Future Recipe Additions
When adding new recipes:
1. Extend evaluator support in `modules/modules/src/crypto/hash_recipe.rs`.
2. Add or update unit vectors in `hash_recipe_vectors`.
3. Add the recipe to this catalog so docs and tests stay aligned.
