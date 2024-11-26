*Work in progress*


## What is this?

This is a manual fork of
<https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f> plus a KEM.  The
goal to keep this in sync on top of
<https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f> so that a diff
shows *only* KEM-related changes.

```sh-session
$ git clone git@gist.github.com:09f4e5682d3b216762cd878e3a8879f0.git dhetm-kem-securedrop
$ cd dhetm-kem-securedrop/
$ git remote add upstream git@gist.github.com:dab18074b9cecb06cbd006e1ab7ede7f.git
$ git fetch upstream
$ git diff upstream/main
```

*(More TK)*


---

Per <https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f#file-readme-md>:

- [x] key generation
- [x] minimal source encryption → journalist decryption
- [x] ephemeral source encryption → journalist decryption
  - [x] verification of $$J$$ and $$NR$$
- [x] ephemeral journalist encryption → source decryption
- [x] ephemeral journalist encryption → journalist decryption
- [x] ephemeral source encryption → source decryption
- [ ] **KEM:** work in progress
- [ ] restore fetching from <https://gist.github.com/lsd-cat/62b05108d7ed7e974efbb805e35eaf28>
- [x] tracing like <https://gist.github.com/cfm/c63561609d2bf621d877dbbef052ab1a> → <https://gist.github.com/cfm/ddbeec52c65f474ce309cb85ae9617aa>
