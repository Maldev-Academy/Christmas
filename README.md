### Christmas

Implementing an injection method mentioned by [@Hexacorn](https://x.com/Hexacorn/status/1350437846398722049?s=20).

This PoC creates multiple processes, where each process performs a specific task as part of the injection operation. Each child process will spawn another process and pass the required information via the command line.  The program follows the steps below:

1. The first child process creates the target process where the payload will be injected. The handle is inherited among all the following child processes.
2. The second child process will allocate memory in the target process. 
3. The third child process will change the previously allocated memory permissions to RWX. 
4. Following that, for every 1024 bytes of the payload, a process will be created to write those bytes.
5. Lastly, another process will be responsible for payload execution.

The PoC uses the RC4 encryption algorithm to encrypt a Havoc Demon payload. The program, `ChristmasPayloadEnc.exe`, will be responsible for encrypting the payload, and padding it to be multiple of 1024 (as required by the injection logic).

</br>

### Demo: Bypassing MDE using Havoc's Demon payload

</br>

![image_2023-12-24_00-31-46](https://github.com/Maldev-Academy/Christmas/assets/111295429/b6af762e-5b76-44a5-834c-a148878a9505)
![image_2023-12-24_00-31-24](https://github.com/Maldev-Academy/Christmas/assets/111295429/fe18b824-21be-4d1f-9bac-1ff798febedf)
