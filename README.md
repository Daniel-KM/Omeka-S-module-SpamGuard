Spam Guard (module for Omeka S)
===============================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Spam Guard] is a module for [Omeka S] that protects public form against spams,
in particular for anonymous interactions with modules [Contact Us], [Annotate],
[Comment], [Contribute], etc. It does not depend on any third piracy service
(google, cloudflare, etc.), so it is GDPR compliant.


Installation
------------

See general end user documentation for [installing a module].

* Composer (recommended, requires Omeka [pull request #2432])

Install the module from the root of Omeka S:

```sh
composer require daniel-km/omeka-s-module-spam-guard
```

The module is automatically downloaded in `composer-addons/modules/` and ready
to enable in the admin interface.

* From the zip

Download the last release [SpamGuard.zip] from the list of releases, and
uncompress it in the `modules` directory. Rename the name of the folder of the
module to `SpamGuard`

* From the source and for development

If the module was installed from the source, rename the name of the folder of
the module to `SpamGuard`.

* For test

The module includes a comprehensive test suite with unit and functional tests.
Run them from the root of Omeka:

```sh
vendor/bin/phpunit -c modules/SpamGuard/phpunit.xml --testdox
```


Quick start
-----------

Once enabled, the module is active with default settings for modules that use
it, like [Contact Us]. Just config the form to set params more precisely.


TODO
----


Warning
-------

Use it at your own risk.

It's always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page on GitLab.


License
-------

This module is published under the [CeCILL v2.1] license, compatible with
[GNU/GPL] and approved by [FSF] and [OSI].

This software is governed by the CeCILL license under French law and abiding by
the rules of distribution of free software. You can use, modify and/ or
redistribute the software under the terms of the CeCILL license as circulated by
CEA, CNRS and INRIA at the following URL "http://www.cecill.info".

As a counterpart to the access to the source code and rights to copy, modify and
redistribute granted by the license, users are provided only with a limited
warranty and the software's author, the holder of the economic rights, and the
successive licensors have only limited liability.

In this respect, the user's attention is drawn to the risks associated with
loading, using, modifying and/or developing or reproducing the software by the
user in light of its specific status of free software, that may mean that it is
complicated to manipulate, and that also therefore means that it is reserved for
developers and experienced professionals having in-depth computer knowledge.
Users are therefore encouraged to load and test the software's suitability as
regards their requirements in conditions enabling the security of their systems
and/or data to be ensured and, more generally, to use and operate it in the same
conditions as regards security.

The fact that you are presently reading this means that you have had knowledge
of the CeCILL license and that you accept its terms.


Copyright
---------

- Copyright Daniel Berthereau, 2026 (see [Daniel-KM] on GitLab)

The idea of this modules comes from a [thread in omeka forum].


[Spam Guard]: https://gitlab.com/Daniel-KM/Omeka-S-module-SpamGuard
[Omeka S]: https://omeka.org/s
[Contact Us]: https://gitlab.com/Daniel-KM/Omeka-S-module-ContactUs
[Annotate]: https://gitlab.com/Daniel-KM/Omeka-S-module-Annotate
[Comment]: https://gitlab.com/Daniel-KM/Omeka-S-module-Contribute
[Contribute]: https://gitlab.com/Daniel-KM/Omeka-S-module-Contribute
[SpamGuard.zip]: https://gitlab.com/Daniel-KM/Omeka-S-module-SpamGuard/-/releases
[installing a module]: https://omeka.org/s/docs/user-manual/modules/#installing-modules
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-SpamGuard/-/issues
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: http://opensource.org
[thread in omeka forum]: https://forum.omeka.org/t/inquiry-about-bot-traffic-control-in-omeka-classic/28800
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
