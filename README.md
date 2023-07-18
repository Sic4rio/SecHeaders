
# Security Headers Checker
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.x-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">

![Banner](shot.png)

Security Headers Checker is a command-line tool to check the security headers of a website. It helps identify missing or misconfigured security headers that can leave a website vulnerable to various attacks.

## Installation

1. Clone the repository:


```
   git clone https://github.com/your-username/security-headers-checker.git
   cd security-headers-checker
```

2. Install the required dependencies:

```

    pip install -r requirements.txt
```
3. Run script

```
python security_headers_checker.py
```
4. Enter the target URL when prompted. The tool will check the security headers of the target website and display the results.

If you have a list of target URLs, you can provide them in a file (one URL per line) and pass the file as a command-line argument:

```

    python security_headers_checker.py 
```
The tool will check the security headers for each URL in the file and provide the results individually.

# Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

License

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0) [![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/stanislav-web)  


This project is licensed under the MIT License.
