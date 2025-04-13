# RIPSv0.5-CLI

A **command-line interface (CLI) version** of [RIPS v0.5](https://github.com/ripsscanner/rips) – a static source code analyzer for detecting vulnerabilities in PHP applications.

This project **removes the web server requirement** and transforms the original **RIPS v0.5** into a **standalone CLI tool**, making it easier to integrate into automated security workflows.

> **🚨 Note:** RIPS v0.5 development is **abandoned** due to its fundamental limitations. A completely new version is available at **[ripstech.com](https://github.com/ripsscanner/rips).**

---

## 📜 Copyright Notice
SEE RIPSv0.5 Copyright file in their [Github](https://github.com/ripsscanner/rips/blob/master/LICENSE)

---

## **⚙️ Requirements**
- **PHP 7.4+** (recommended PHP 8.0+ for better performance)
- **No external dependencies** (Runs as a standalone script)

---

## **🚀 Installation**
### **Option 1: Download the Release Version**
We provide a **standalone release version** that does not require additional dependencies. You can download it from the **Releases** section.

```sh
wget https://github.com/YichaoXu/ripsv0.5-cli/releases/download/v0.5-2025.02.24/ripsv0.5-cli.phar
chmod +x rips.phar
```

Now you can run it directly:
```sh
php ./rips.phar /path/to/php/code --vector=xss --format=json
```

### **Option 2: Clone the Repository**
```sh
git clone https://github.com/Yichao/RIPSv0.5-cli.git
cd RIPSv0.5-cli
php rips.php /path/to/php/code
```

---

## **📌 Usage**
### **Basic Syntax**
```sh
php rips.php /path/to/php/code [options]
```

### **Options**
| Option | Description |
|--------|-------------|
| `--vector=<type>` | Set the attack vector (`xss`, `sql`, `exec`, `include`, `all`). Default: `all`. |
| `--verbosity=<level>` | Set verbosity level (`1-5`). Default: `1`. |
| `--format=<type>` | Output format (`readable`, `json`). Default: `readable`. |
| `--ignore_warning` | Ignore file count warnings. |
| `--help` | Show usage information. |

### **Example Commands**
#### **1️⃣ Scan a PHP project**
```sh
php rips.php /var/www/html --vector=xss --format=json
```
#### **2️⃣ Scan with verbose output**
```sh
php rips.php /var/www/html --vector=sql --verbosity=3
```

---

## **🔨 Development**
- This CLI version refactors **RIPS v0.5** into a command-line tool.
- The project removes **web UI dependencies** and replaces **PHP's `$_POST`** inputs with CLI arguments.
- **Includes JSON output support** for easy integration with automation and CI/CD.

---

## **⚠️ Disclaimer**
- This tool is based on **RIPS v0.5**, which is no longer maintained.
- Use the tool **at your own risk**, as it does not reflect modern PHP security best practices.
- For modern static code analysis, consider **[ripstech.com](https://www.ripstech.com)**.
- If you use this cli wrapper, please also consider to cite [our work](not_release_now)

---

## **📜 License**
RIPS v0.5 is licensed under **GPL-3.0**. This project follows the same license.

---

### **🔗 Links**
- [Original RIPS v0.5 Repository](https://github.com/ripsscanner/rips)
- [Latest RIPSv0.5-CLI Release](https://github.com/YichaoXu/RIPSv0.5-cli/releases)

