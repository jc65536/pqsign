# PQCSoftwareUpdate
We study the software update scheme with post quantum signature.

# How to sign your commit?

Since we are working at signing software update, we should also sign each of our commit.
Please generate a GPG key pairs:

https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key

And then set the following configuration for your local git:
```bash
git config --local commit.gpgsign true
gpg --list-secret-keys --keyid-format LONG
```

After you get you long secret key, config it as:
```bash
git config --local user.signingkey "[GPG_KEY]"
```

In windows, you might need to configure your gpg path:
```
where.exe gpg
git config --global gpg.program [PATH_HERE]
```
