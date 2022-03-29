import ./wordlist
import tables, macros, strformat
export tables, wordlist

macro wordlistOf*(language: string, body: untyped): untyped =
    let getter = ident(&"get_{language.strVal}")

    quote do:
        var list = WordList(
            words: newSeq[string](),
            reverseWords: newTable[string, Natural](),
            language: `language`)

        template mnemonic(word: string): untyped =
            list.reverseWords[word] = list.words.size
            list.words.add(word)

        template `getter`(): WordList = list

        `body`
