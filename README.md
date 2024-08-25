# Trust PDF

A library to verify that a signed PDF is valid, and matches the unsigned original.

## The Problem

Imagine this scenario: you generate a PDF file with your terms and conditions
and send to your customer or business partner to be signed. The other party
signs it and uploads it to your server.

For all you know about digital documents and signatures, it should be trivially
easy for your server to verify the validity of the signature, and that the
signed document they submited is actually the same document you sent to them,
right?

**WRONG!**

It is unreasonably hard to decide if the contents of a signed PDF file you are
given corresponds to the unsigned version you wrote and trust! It doesn't seems
to be any established, true and tested protocol or standard on how to do that,
nor does it seems that the writers of the PDF standard gave any thought to the
problem.

Which is kind of understandable, after all, PDF standard assumes there is an
actual GUI, with an actual person reading the file, and that this person will
read it again after it was signed and sent back, and will watch the PDF embedded
videos, and execute the PDF embedded JavaSripts. But since you are automating
the process, you should be instead dealing with PKCS #7 files with the PDF
ebedded in them, and not the other way around (and if that was the case, the
task would be indeed trivial).

But in the real world, we have governments running online tools for generating
legally binding digital signatures for its citizens, where the only possible
output is a signed PDF, who became the de-facto standard for digitally signed
documents, and we have to find a way to automatically deal with them.

This library is my attempt to tackle the problem, and it will work as long as
the signature is added in an specific and restricted way.

## The Difficulty

The problem is that the PDF is a complex format with lots of moving parts, and
the embedded signature is just another object of its internal structure. In
fact, it is handled by PDF as if it is a form field (and sometimes an
annotation, with the visible drawing that users think is the actual signature,
but is not). So, to include a signature, you have to necessarily change the PDF
file in non-trivial ways, with limtless degrees of freedom and choices on how to
do it.

Word is that Adobe Acrobat will deserialize all the PDF objects into memory, add
the new signature objects and then re-serialize it in a completely new save.
Thus any hope of trivial byte-to-byte comparison goes out of the window.

But there is a glimmer of hope in an alternative way of modifying a PDF file,
called incremental update. The PDF signers I have tested will actually use this
method, and if the original PDF has the proper `/SigFlags` set, even Acrobat
will use it. It works by taking the original PDF bytes verbatim, and appending
the new content. The original file becomes a prefix for the new file.

One might think that you just have to check if the orignal file is a prefix of
the signed file to ensure it was not modified, and one would be wrong. An
incremental update can change absolutelly everything about a PDF file. It
actually has to provide a new index for the PDF objects, which might optionally
use the objects in the original file, but it doesn't have to. And a signature
included in such way will not only sign the original file range, it will sign
everything, including the incremental update itself, so you can't have your
lawyers argue that what was signed was actually the prefix document, and not the
modified one.

## The Strategy

To solve the problem, this library whitelists what can be done in order to add
signatures in the document:

* The signed document must start with the unsigned document;
* Every added signature must have its own incremental update;
* Each incremental update must keep unmodified all the objects in the previous
  increments, except the ones strictly necessary to change: the `/Catalog`, the
  `/AcroForm` and at most one `/Page`;
* In the `/Catalog`, only `/AcroForm` and a couple of other fields can be added,
  if missing;
* In `/AcroForm`, a single extra `/FT /Sig` form field must be added;
* In at most one of the pages, a single annotation of `/Subtype /Widget` can be
  added;
* The signatures must be valid, and cover from the beginning of the document to
  the end of their incremental update;
* The final signature must cover the entire document.

It is my hope that this will suffice to prevent any content modification of the
rendered PDF, with the exception of the signature annotation, which might be
crafted and placed somewhere to meaningfully change the interpretation of the
contents. To mitigate that, this library will also return the page and the
rectangle of each signature annotation, for further whitelisting by the
application.