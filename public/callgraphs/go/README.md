# Call Graph Visualization

To visualize the call graph in interactive mode, please follow the steps below:

## Step 1: Install go-callvis

To install `go-callvis`, follow the steps provided on the [go-callvis GitHub page](https://github.com/ondrajz/go-callvis#installation).

## Step 2: Clone this Project

Clone the project repository using your preferred method.

## Step 3: Generate and Interact with the Call Graph

1. Open your terminal or command prompt.

2. Navigate to the project directory.

3. Run the following command to generate and interact with the call graph:

```sh
go-callvis -algo=rta -graphviz -nodeshape=plaintext ./cmd/tarian_detector/
```

![call graph main package](./main.svg)