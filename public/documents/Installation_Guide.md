# 🚀 Tarian Detector Installation Guide

Welcome to the step-by-step installation guide for Tarian Detector. This guide will help you install and run Tarian Detector on your local machine. 

## ⚙️ Prerequisites

Before starting, ensure you have the following dependencies installed on your system:

- 🐭 Go programming language (version 1.16 or higher)
- 🎯 Clang compiler
- 🧪 LLVM
- 📚 libelf development library
- 🔧 libbpf development library
- 🐧 Linux kernel headers
- 🛠️ Linux tools (matching your kernel version)
- 🧰 bpftool utility

You can install these dependencies by running the following command:

## Install Project Dependencies:

```bash
make install
```

## 📥  Clone the Repository 

Clone the Tarian Detector repository to your local machine:

``` bash
git clone https://github.com/your-username/tarian-detector.git
cd tarian-detector
```

## 🏗️  Building Tarian Detector

After you've successfully cloned the repository and installed the necessary dependencies, it's time to build the project.

Navigate to the root directory of Tarian Detector:

```bash
cd tarian-detector
```
Then build the project using the provided Makefile:

```bash
make build
```

## 🏃‍♂️ Running Tarian Detector

You've successfully built the project! Now, you can run Tarian Detector on your machine:

```bash
make run
```


## 🧪 Development and Testing

For development purposes, the Makefile provides a helpful command to build and run the application in one step:

```bash
make dev_run
```

To ensure your code adheres to our standards and does not contain any issues, use our linting tools:

```bash
make fmt    # Run go fmt to format Go code
make lint   # Run linting with revive and staticcheck for Go code

```

This command executes go fmt, go vet, and additional linting tools against your code.

## 📜 Create a File with License and Copyright Details:


To create a new file with license and copyright details, run:

```bash
make file FILE_PATH=/your/file/path/filename.ext
```


## 🚫 Uninstall 
If you ever want to uninstall Tarian Detector and remove its dependencies, run:

``` bash
make uninstall
```

##  🧹 Clean-Up 
If you want to clean up the project and remove object files, run:

```bash
make clean
```

That's it! You have successfully installed Tarian Detector and can now use it to detect whatever it is designed for. Please note that the specific functionalities and details of Tarian Detector may vary based on the actual project. Always refer to the project's documentation for more information on its usage and capabilities.

## 🎉  Wrapping Up

Congratulations! You've successfully installed and run Tarian Detector on your local system. For any questions or issues, please refer to the Troubleshooting and FAQs or [Contact Us](https://intelops.ai/contact/). We're here to help!




