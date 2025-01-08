# Contributing to CONTRIBUTING.md

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways
to help and details about how this project handles them. Please make sure to read the relevant section before making
your contribution. We look forward to your contributions. 🎉

> If you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support
> the project and show your appreciation, which we would also be very happy about:
> - Star the project
> - Tweet about it
> - Refer this project in your project's readme
> - Mention the project at local meetups and tell your friends/colleagues

## Table of Contents

- [Reporting Bugs](#reporting-bugs)
- [Security Issues](#security-issues)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Commit Messages](#commit-messages)
- [Building a release](#release-building)
- [Legal Notice](#legal-notice)

## Reporting Bugs

We love to hear about issues and bugs! You may open a github issue right in this repository.
In addition to the bug you found, please mention the version you are using and the behavior
you would expect.

> ### Security issues
> Please don't add vulnerabilities or bugs including sensitive information to the issue
> list, or elsewhere in public. Instead sensitive bugs should be sent by email to support@productaize.io

We use GitHub issues to track bugs and errors. If you run into an issue with the project:

- Open an [Issue](/issues/new). (Since we can't be sure at this point whether it is a bug or not, we ask you not to talk
  about a bug yet and not to label the issue.)
- Explain the behavior you would expect and the actual behavior.
- Please provide as much context as possible and describe the *reproduction steps* that someone else can follow to
  recreate the issue on their own. This usually includes your code. For good bug reports you should isolate the problem
  and create a reduced test case.
- Provide the information you collected in the previous section.

Once it's filed:

- The project team will label the issue accordingly.
- A team member will try to reproduce the issue with your provided steps. If there are no reproduction steps or no
  obvious way to reproduce the issue, the team will ask you for those steps and mark the issue as `needs-repro`. Bugs
  with the `needs-repro` tag will not be addressed until they are reproduced.
- If the team is able to reproduce the issue, it will be marked `needs-fix`, as well as possibly other tags (such as
  `critical`), and the issue will be left to be [implemented by someone](#your-first-code-contribution).

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for CONTRIBUTING.md, **including completely new
features and minor improvements to existing functionality**. Following these guidelines will help maintainers and the
community to understand your suggestion and find related suggestions.

Enhancement suggestions are tracked as [GitHub issues](/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description of the suggested enhancement** in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see instead** and why. At this point
  you can also tell which alternatives do not work for you.
- **Explain why this enhancement would be useful** to most CONTRIBUTING.md users. You may also want to point out the
  other projects that solved it better and which could serve as inspiration.

## Commit messages

We use conventional commits](https://www.conventionalcommits.org/) in a non-dogmatic
manner (use your good judgement). Here are some typical commit messages that we like:

Maintenance

    chore: update dependencies

    - update setuptools

Bug fixing

    fix: foo does not print bar

    - fixes #12345

New Features

    feat: foo now prints bar

    - closes #12345

Documentation

    doc: describe foo and bar interaction

    - closes #12345

## Release building

This project uses [semantic versioning](https://semver.org/). To automate release
building, we use [bump2version](https://github.com/c4urself/bump2version) for release naming,
and a Makefile to tie everything together.

The process is as follows:

1. create a clean branch to build the release from. This will bump the release and
   create a new release name (incrementing the patch part of major.minor.patch,
   and adding a -dev1 tag to it)

        $ git checkout -b prepare-release
        $ make bump-release

2. test the release (optional). this will test and build the release, publish it to  
   pypi-test and install it back. If this works, everything works technically

        # this will ensure you have a -rc release, otherwise shows an error
        $ make test release-test

3. publish the release. This will again test and build the release, and publish
   it to pypi. It will also create a commit, tag the release and push everything
   to the repo.

        # this will ensure you have a final release, otherwise shows an error
        $ make release

   > Once published a release cannot be undone. Thus be sure to test first.

4. Create a pull request from the release. No code changes should be in this
   pull request.

## Legal Notice

> When contributing to this project, you agree that you have authored 100% of the content, that you have the
> necessary rights to the content and that the content you contribute may be provided under the project license (MIT).

This guide is based on the **contributing.md**. [Make your own](https://contributing.md/)!

