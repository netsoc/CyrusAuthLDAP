# Source/Credit

The original cyrusauth file modified to create this one was retrieved using
apt-get source znc on Debian "Jessie". The changes should work if copied as-is
to the source available on github or elsewhere, as is relevant to your system.

# Compiling the Module

However, for cyrusauthldap to work, `cyrusauthldapLDFLAGS := -lsasl2` has to be
added to the Makefile in modules/ in the souce. Try `cat Makefile | grep
cyrusauth` to see that this has been done for cyrusauth as well.

Note, you may need to run `./configure --enable-cyrus` for this to work.
Similarly, you most likely need to have installed znc with cyrusauth enabled,
which has been the default since 1.0.

# Running the Module

Once it's compiled and the .so file put in the currently installed ZNC's
modules/ directory, connect to znc and `/msg *status loadmod cyrusauthldap
saslauthd`, then set CreateUser to yes, set up CloneUser with a base user and
set CreateFromLDAP to yes.
