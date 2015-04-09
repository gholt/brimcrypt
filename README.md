# BrimCrypt
## Crypto Tools for Go

Package brimcrypt contains crypto-related code including an encrypted disk file
implementation of io.Reader, Writer, Seeker, and Closer. The encryption used is
AES-256 with each block signed using SHA-256.

[API Documentation](http://godoc.org/github.com/gholt/brimcrypt)

This is the latest development area for the package.  
For the latest stable version of the package, switch to the
[v1 branch](https://github.com/gholt/brimcrypt/tree/v1)  
or use `gopkg.in/gholt/brimcrypt.v1` as the import path.  
Also, you'd want to use the
[V1 API Documentation](http://godoc.org/gopkg.in/gholt/brimcrypt.v1).

> Copyright Gregory Holt. All rights reserved.  
> Use of this source code is governed by a BSD-style  
> license that can be found in the LICENSE file.
