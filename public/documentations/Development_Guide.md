# 🚀 Tarian Detector Development Guide

Welcome to the development guide for Tarian Detector. This guide will help you understand how to contribute to the development of Tarian Detector.

## 📖 Table of Contents

- [Setting Up the Development Environment](#🧑‍💻-setting-up-the-development-environment)
- [Understanding the Repository Structure](#🗄️-repository-structure)
- [File Contribution Guide](#file-contribution-guide)
- [Development Workflow](#🔄-development-workflow)
- [DCO Signoffs](#✍️-dco-signoffs)
- [Testing](#🧪-testing)
- [Code Reviews](#👀-code-reviews)
- [Documentation](#📚-documentation)
- [Acceptance Policy](#✅-acceptance-policy)

## 🧑‍💻 Setting Up the Development Environment

Before you start contributing to Tarian Detector, you need to set up your development environment. Follow these steps:

1. Fork the [Tarian Detector](https://github.com/intelops/tarian-detector) repository on GitHub to your personal account.
2. Clone the forked repository to your local machine.
    ```bash
    git clone https://github.com/<your-username>/tarian-detector.git
    cd tarian-detector
    ```
3. Install the project dependencies as described in the [Installation Guide](./Installation_Guide.md).

## 🗄️ Repository Structure

The Tarian Detector project has been structured in a specific way to ensure easy navigation and efficient project management. As a contributor, understanding this structure is vital to ensure your contributions are correctly placed and easy for others to find and understand.

Our `Repository Structure Guide` provides an in-depth walkthrough of the layout of the project, highlighting where specific files are located, where new files should be added, and what each directory and file is used for. This guide serves as a roadmap to the project, helping you quickly find what you're looking for, understand how various parts of the project are related, and see where your contributions should fit in the grand scheme of the project.

In the `Repository Structure Guide`, you will also find explanations of naming conventions, file formats, and other standards that have been established for the project. Adhering to these standards helps ensure consistency and quality across all contributions.

Check out the [Repository Structure Guide](Repository_Structure.md) for more detailed information and to familiarize yourself with the inner workings of the Tarian Detector project.

# File Contribution Guide

If you're adding new files to the project, please see our [File Contribution Guide](./File_Contribution%20_Guide.md). 
This guide provides an overview of our repository structure and offers a step-by-step walkthrough on how to add new files. It addresses how to name your files, where to correctly place them within our project hierarchy, and how to document your changes. 

Whether you're contributing code, documentation, graphics, or other types of files, we have a place for them all. By following this guide, you'll ensure your contributions fit seamlessly into our project, making it easier for everyone involved in the Tarian Detector project.

## 🔄 Development Workflow

The Tarian Detector uses a typical Git development workflow. If you are not familiar with it, here's an overview:

1. Create a new branch for each feature, improvement, or bugfix you are working on.
    ```bash
    git checkout -b <branch-name>
    ```
2. Make your changes to the codebase. Remember to follow the code style guidelines described in the [Styling Guide](#🎨-styling-guide).
3. Commit your changes. Each commit should contain a clear commit message describing the changes.
    ```bash
    git commit -m "Describe your changes here"
    ```
4. Push your changes to your forked repository on GitHub.
    ```bash
    git push origin <branch-name>
    ```
5. Open a pull request from your forked repository to the `dev` Tarian Detector repository.
6. Wait for a review from one of the project maintainers. They may suggest some changes or improvements.
7. Once your pull request has been approved, it will be merged into the main codebase.

## 🎨 Styling Guide

When contributing to the Tarian Detector project, please follow these code styling conventions. Consistent code style across the project makes it easier for everyone to read and understand the code.

### General Guidelines

- Indent your code with 4 spaces, not tabs.
- Keep line lengths under 80 characters when possible.
- End files with a single newline character.

### C Kernel Programming

We recommend the use of the clang-format tool that can import a list of predefined rules, automatically formatting the code for us. 

Check out these references:
- [The International Obfuscated C Code Contest](https://www.ioccc.org/2020/carlini/prog.c)
- [Kernel Documentation: Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- [FreeBSD Man Pages: Style](https://www.freebsd.org/cgi/man.cgi?query=style&sektion=9)
- [Clang Format](https://clang.llvm.org/docs/ClangFormat.html)

Further reading:
- [Kroah-Hartman, Greg, Documentation/CodingStyle and Beyond](https://landley.net/kdocs/ols/2002/ols2002-pages-250-259.pdf)

### Golang

For Golang, we follow the [Effective Go](https://golang.org/doc/effective_go.html) style guide from the official Go documentation. You can also run the [gofmt](https://golang.org/cmd/gofmt/) tool to automatically format your Go code.

## ✍️ DCO Signoffs

All commits must include a DCO signoff line in the commit message (`Signed-off-by: Your Name <your-email@example.com>`). This indicates that you agree your contributions will be licensed under the project's license.

To automate the signoff process, you can use the `-s` flag when committing:
```bash
git commit -s -m "This is my commit message"
```
This will append the required `Signed-off-by` line to your commit message.


## 🧪 Testing

After you've made changes to the codebase, ensure you run the tests to confirm that your changes have not broken anything.

Please also add new tests when you add new features or fix bugs.

Follow the [Testing Guide](./Testing_guide.md).

## 👀 Code Reviews

Code reviews help ensure the quality of our codebase. Here are a few tips:

- Always be respectful and considerate in your reviews. Remember that everyone is doing their best.
- Be explicit and clear. Explain your reasoning.
- Request feedback on parts of the code you're unsure about.

## 📚 Documentation

We strive to have a high-quality, up-to-date documentation. If you make changes to the user interface or APIs, please also update the relevant documentation.

## ✅ Acceptance Policy

To maintain the quality of the Tarian Detector project, we have an acceptance policy for all new code contributions:

- **All Tests Must Pass**: Before any pull request is accepted, all automated tests must pass. If your pull request breaks any tests, it will be rejected until the tests are fixed.
- **Code Quality**: Your code should follow the style guide as outlined in the Contributor's Guide. Code that doesn't adhere to the style guide may be rejected or require revisions before acceptance.
- **Documentation**: If your change affects how users or developers interact with the project, it must include updates to the corresponding documentation.
- **Sign-off on Commits**: All commits must be signed off by the author, indicating agreement with the DCO Signoffs policy.
- **Approval**: Finally, the pull request must be reviewed and approved by at least one of the project maintainers.

Please understand that these policies are in place to ensure the continued high quality and consistency of Tarian Detector project.

## 🎉 Wrapping Up

Congratulations, you're now ready to contribute to the Tarian Detector project! Remember, we appreciate all contributions, no matter how small. Even fixing a small typo in the documentation can be a great help. Happy coding!
