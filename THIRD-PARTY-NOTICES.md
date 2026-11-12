# Third-party notices

idasql is licensed under the Human-Origin Source License v1.0 (see `LICENSE`). The notices below
cover third-party work it includes or reimplements.

## ida-hcli

https://github.com/HexRaysSA/ida-hcli

Parts of the `idasql link` support reimplement in C++ the behaviour of Hex-Rays' ida-hcli: the
client for IDA's IPC endpoints, launching IDA on a database, and registering the `ida://` URL
handler. idasql does not need hcli installed.

```
MIT License

Copyright (c) 2025 Hex-Rays SA

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
