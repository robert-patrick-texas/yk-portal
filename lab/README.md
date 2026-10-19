# The yk-portal lab

yk-portal installed as [the deployment guide](../docs/deployment.md) installs
it, in a Docker container, reachable only through the host's nginx, which
publishes it under a path of one of the host's sites (or a host name of its
own). Bring it up to try a change in a real browser, behind a real proxy,
and take it down afterwards: nothing is kept, and while it is down nginx
answers 502 at its address. Not for production.

The lab's address and port are this machine's: they go in `lab/lab.env`,
which git ignores, never in the repository. Once:

```bash
cp lab/lab.env.example lab/lab.env
editor lab/lab.env      # YK_LAB_PUBLIC_BASE_URL, YK_LAB_PORT
```

Then:

```bash
lab/lab up                          # build and start, with SQLite
lab/lab up --postgresql             # or with PostgreSQL 18 and psycopg's C implementation
lab/lab up --deb dist/yk-portal_1.0.0-1_amd64.deb   # or installed from the package
lab/lab yk-portal bootstrap-admin root
lab/lab status
lab/lab logs -f
lab/lab yk-portal database-status   # any yk-portal command, as the yk-portal account
lab/lab shell
lab/lab down
lab/lab systemd-check               # yk-portal.service under systemd, sandboxed
lab/lab systemd-check --deb dist/yk-portal_1.0.0-1_amd64.deb   # the package's, and its upgrades
```

`lab/lab up` builds the image from the working tree (`lab/Dockerfile`: Ubuntu
26.04, uv, `deploy/install`; or, with `--deb`, the package, which
`packaging/deb/Dockerfile` builds into `dist/`), and runs it on a Docker network of its own,
`yk-portal-lab`, published on the host's `127.0.0.1` only, at `YK_LAB_PORT`
(8100 if not set). At each start, `lab/entrypoint` writes the configuration
(`public_base_url` from `YK_LAB_PUBLIC_BASE_URL`; the network's gateway,
where Docker's port forwarding connects from, as the trusted proxy), creates
the master key the first time, migrates, and runs `yk-portal serve` as the
`yk-portal` account. The audit log's copy goes to the host's journal
(`journalctl -t yk-portal-audit`).

With `--postgresql`, a `postgres:18` container on the same network holds the
database, set up as the guide sets up PostgreSQL: a role that owns the
database, its password in a passfile.

`lab/lab systemd-check` builds `lab/Dockerfile.systemd` (the lab image with
systemd as its init), starts `yk-portal.service` under systemd with its whole
sandbox in a privileged container with no network, signs in, checks the
journal and the database file, prints `systemd-analyze security`'s rating,
checks that the unit ends failed without its master key, and removes the
container. With `--deb`, `lab/deb-check` checks the package's maintainer
scripts there too, first an upgrade (backed up, migrated, running again), an
upgrade whose backup fails (stopped, nothing changed), one with
`YK_PORTAL_UPGRADE_BACKUP=no`, and one onto a database newer than the package
(stopped before the start, finished by `dpkg --configure -a`); and last,
removal, a first install again, purge, and the package refusing to go over
an installation from source. The release workflow runs it on every release.

Where containers can't reach the Internet through Docker's default network,
set `YK_LAB_BUILD_NETWORK=host` (in `lab/lab.env` or the environment) for the
image builds.

## The host's nginx, once

Two files, as for any site with yk-portal under a path, and one line in the
site's `server { }` block. The files publish the lab at `/yk/` with the
upstream port 8100: change the path to `YK_LAB_PUBLIC_BASE_URL`'s and the
port to `YK_LAB_PORT` first. Here `SITE` is the site's file:

```bash
sudo install -m 0644 lab/nginx/yk-portal-lab.conf /etc/nginx/conf.d/yk-portal-lab.conf
sudo install -m 0644 lab/nginx/yk-portal-lab-location.conf /etc/nginx/snippets/yk-portal-lab.conf
sudoedit /etc/nginx/sites-available/SITE   # add in server { }: include snippets/yk-portal-lab.conf;
sudo nginx -t && sudo systemctl reload nginx
```

To remove it, delete the line and the two files, then test and reload again.
If the site adds its own security headers to every response, some arrive
twice (such as `X-Frame-Options` as both `DENY` and `SAMEORIGIN`, which
browsers treat as `DENY`); a host name of the lab's own wouldn't. Under a
path, yk-portal sends no HSTS header: the site's own applies.
