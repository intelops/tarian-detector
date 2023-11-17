# Current Support

The project currently supports kernel versions 5.8.0 to 6.12.0 (inclusive).

We have conducted random tests on kernel versions >=5.0.0 on Ubuntu machines, and our project is working without any issues on kernel versions >= 5.8.0.

>Given the nature of our product, it's essential to ensure its compatibility and performance across different kernels and Linux distributions. We plan to conduct >comprehensive testing on:
>
>**Various Linux Kernels** : To ensure our product performs optimally across different kernel versions.
>
>**Different Linux Distributions** : Test our product on multiple distributions to confirm its broad compatibility.


# Supporting Evidence

To ensure broader compatibility, we have performed testing on the following kernel versions:

- Kernel version 5.8.0
  ![Kernel version 5.8.0](images/testing/5.8.0-aws.png)

- Kernel version 5.9.0
  ![Kernel version 5.9.0](images/testing/5.9.0-aws.png)

- Kernel version 5.12.0
  ![Kernel version 5.12.0](images/testing/5.12.0-aws.png)

- Kernel version 5.16.11
  ![Kernel version 5.16.11](images/testing/5.16.11-aws.png)

- Kernel version 5.19.0
  ![Kernel version 5.19.0](images/testing/5.19.0-local.png)

# How We Tested Our Project?

To ensure the stability and compatibility of our project, we followed these steps:

1. **Built the project in the local development environment**.

2. **Exported the generated executable to a virtual machine**.

3. **Booted the virtual machine with the desired kernel version**.

4. **Executed the project's executable on the virtual machine**.

# Future Plans

We are committed to improving compatibility and expanding the scope of our testing. Our future plans include:

- Adding support to test code on more kernel versions and different Ubuntu flavors.

- Striving to add more detailed output information for a wider range of environments.

We value user feedback and encourage the community to report any issues they encounter on different setups. This will help us enhance the overall compatibility and robustness of our project.
