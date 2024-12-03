# binSpectreDefense
protect executable files under ARM architecture against spectre
***
We used binary rewriting techniques to defend against the Spectre attack on the ARM architecture.
## 项目简介
本项目可以实现在ARM架构下使用retrowrite工具实现对二进制文件的插桩从而防御spectre攻击代码

## 项目引用

- retrowirte：[GitHub](https://github.com/HexHive/retrowrite.git)
- libtea：[GitHub](https://github.com/libtea/frameworks) 

## 硬件环境

ARM架构 
官网：https://www.arm.com/

## 软件环境

| 设备                  |       设备版本       | 说明                  | 官网                               |
|---------------------|:--------------:|---------------------| --------------------------------------- |
| kali              | >=2021.1       | 操作系统        | [进入](https://old.kali.org/arm-images/)  |
| python            |     >=3.8      | python环境             | [进入](https://www.python.org/)                  |  
| clang       |     >=9.0.1-14     | clang编译器       | [进入](https://clang.llvm.org/)                   | 


## 实验测试
1.在树莓派上使用对应的clang编译器编译准备好的spectre.c代码
![image](https://github.com/user-attachments/assets/015bed15-7901-4143-af28-581ee9bc7161)
2.使用retrowrite工具对目标二进制文件反汇编，反汇编为patch.s
![image](https://github.com/user-attachments/assets/281ff2f1-8165-457e-b824-6eeff2a324e6)
3.在patch.s中插入对应的汇编指令，完成插桩
![image](https://github.com/user-attachments/assets/9482faa4-dc3f-490d-a760-d46e0b9493e0)
4.使用retrowrite工具将patch.s编译二进制文件patch
![image](https://github.com/user-attachments/assets/9b326867-a0de-4951-bce5-c9baddb191dc)
5.运行插桩后的二进制文件patch，完成对spectre攻击的防御
![image](https://github.com/user-attachments/assets/69b2f673-8699-4b54-87f6-9d2837e8a4ca)

