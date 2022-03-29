import tables

type
    WordList* = object
        words*: seq[string]
        reverseWords*: TableRef[string, Natural]
        language*: string
