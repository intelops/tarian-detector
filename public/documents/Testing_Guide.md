# Testing Guide for Tarian Detector

This document provides a guide on how to test the Tarian Detector project.

## Unit Tests

Unit tests are used to test individual components of the software in isolation. Here's how you can run unit tests:

```bash
sudo go test ./...
```

## Test Coverage

Test coverage is a measure of the amount of testing performed by a set of tests. It includes everything from the percentage of your codebase covered by tests, to the number of use-cases or scenarios covered.

Whenever new code is added, it’s important to check the test coverage to ensure that the new code is adequately tested. You can check the test coverage by running the following command:

```bash
sudo go test ./... -cover
```

For a more detailed view of the test coverage, you can generate a coverage profile and then convert it into an HTML report using these commands:

```bash
sudo go test ./... -coverprofile=coverage.out
sudo tool cover -html=coverage.out
```

This will provide a visual representation of which parts of your code are covered by tests.

## Reporting Issues

If you encounter any issues while testing, please report them by creating an issue in the GitHub repository.

Remember to provide as much information as possible in your issue report, such as the steps to reproduce the issue, the expected and actual results, and any relevant error messages.

## Conclusion

Testing is a crucial part of software development that helps ensure the quality and reliability of the software. Thank you for taking the time to test the Tarian Detector project!
