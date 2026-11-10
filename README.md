# NIGHTSHIFT Cyber Range

A responsive, static cyber-security learning dashboard with an interactive **simulated** terminal. Built as a safe educational experience: it does not execute operating-system commands, install real hacking tools, access files, send network traffic, or connect to real targets.

## Run locally

Serve the repository root with any static server, for example:

```sh
python3 -m http.server 4173 --bind 0.0.0.0
```

Then open `http://localhost:4173`.

## Safe terminal commands

`help`, `clear`, `pwd`, `whoami`, `date`, `ls`, `status`, `tools`, `scan lab.local`, `inspect lab.local`, `audit demo.local`, `hash demo.txt`, and `echo <text>` are canned simulations using fictional training data. Unsupported commands are refused; no shell is invoked.

## Deploy

The site is a static HTML/CSS/JS app and can be deployed directly to Vercel with the repository root as the output directory.
