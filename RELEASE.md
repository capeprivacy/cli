# Release

Before releasing the CLI make sure to check the most recent release version by running the following:

```
git fetch
git tag
```

The output from `git tag` will look something like:

```
....
v0.1.1
v0.1.2
v0.1.3
v0.1.4
```

Depending on the most recent changes you would increment the next version to `v0.1.5`, `v0.2.0` or `v1.0.0`. See https://semver.org/ for more information on why you might increment different numbers in the version.

To do the actually release you just run the following with the correct versions:

```
git tag v0.1.5
git push origin v0.1.5
```

This triggers an action on github to automatically build and push the release to github. You will get an email once it completes or fails and it will now be available at the following URL: https://github.com/capeprivacy/cli/releases/latest.
