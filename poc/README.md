Pull submodules: 
git submodule update --init --recursive

If you get an error: Permission denied (publickey)
https://docs.github.com/en/authentication/troubleshooting-ssh/error-permission-denied-publickey
Make sure your GitHub public key is also loaded into ssh-agent

make clean
make 
make vectors

sage --pip install -r requirements.txt

