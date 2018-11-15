# ChangeLog 
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 1.0.5 - 2018-11-15
### Changed

- Support for only uploading rules that actually changed on local disk
- Fix bug where uploader would fail if there were no rules present in auth0

## 1.0.4 - 2018-06-29
### Changed

- Python 36<365 fix for logging and utf8

## 1.0.3 - 2018-06-06
### Changed

- Python 34 fix

## 1.0.2 - 2018-04-10
### Changed
- Install scripts as.. scripts so that you can use them directly after a `pip install auth0-ci`
- Removed unused open() call in setup.py

## 1.0.1 - 2018-03-30
### Added
- Support for local `credentials.json` file in addition to CLI
- Support for updating auth0 client files, with diffing
- Support logging to syslog, and verbose/debug options

### Added
- Support for loading credentials from `credentials.json` in addition to CLI, for all scripts

## 1.0.0 - 2018-03-08
### Added
- This ChangeLog
- Initial import from https://github.com/mozilla-iam/auth0-scripts
