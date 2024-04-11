(function() {var type_impls = {
"gimli":[["<section id=\"impl-Eq-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-Eq-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section>","Eq","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-Hash-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;__H: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>&gt;(&amp;self, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.reference.html\">&amp;mut __H</a>)</h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.75.0/src/core/hash/mod.rs.html#242-244\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.slice.html\">[Self]</a>, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.reference.html\">&amp;mut H</a>)<span class=\"where fmt-newline\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</span></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/1.75.0/core/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Endianity-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#215-220\">source</a><a href=\"#impl-Endianity-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"gimli/trait.Endianity.html\" title=\"trait gimli::Endianity\">Endianity</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.is_big_endian\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#217-219\">source</a><a href=\"#method.is_big_endian\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#tymethod.is_big_endian\" class=\"fn\">is_big_endian</a>(self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Return true for big endian byte order.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.is_little_endian\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#13-15\">source</a><a href=\"#method.is_little_endian\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.is_little_endian\" class=\"fn\">is_little_endian</a>(self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Return true for little endian byte order.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_u16\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#23-30\">source</a><a href=\"#method.read_u16\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_u16\" class=\"fn\">read_u16</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u16.html\">u16</a></h4></section></summary><div class='docblock'>Reads an unsigned 16 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_u16\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_u32\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#38-45\">source</a><a href=\"#method.read_u32\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_u32\" class=\"fn\">read_u32</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u32.html\">u32</a></h4></section></summary><div class='docblock'>Reads an unsigned 32 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_u32\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_u64\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#53-60\">source</a><a href=\"#method.read_u64\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_u64\" class=\"fn\">read_u64</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u64.html\">u64</a></h4></section></summary><div class='docblock'>Reads an unsigned 64 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_u64\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_uint\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#68-76\">source</a><a href=\"#method.read_uint\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_uint\" class=\"fn\">read_uint</a>(&amp;mut self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u64.html\">u64</a></h4></section></summary><div class='docblock'>Read an unsigned n-bytes integer u64. <a href=\"gimli/trait.Endianity.html#method.read_uint\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_i16\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#84-86\">source</a><a href=\"#method.read_i16\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_i16\" class=\"fn\">read_i16</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.i16.html\">i16</a></h4></section></summary><div class='docblock'>Reads a signed 16 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_i16\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_i32\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#94-96\">source</a><a href=\"#method.read_i32\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_i32\" class=\"fn\">read_i32</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.i32.html\">i32</a></h4></section></summary><div class='docblock'>Reads a signed 32 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_i32\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_i64\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#104-106\">source</a><a href=\"#method.read_i64\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_i64\" class=\"fn\">read_i64</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.i64.html\">i64</a></h4></section></summary><div class='docblock'>Reads a signed 64 bit integer from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_i64\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_f32\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#114-116\">source</a><a href=\"#method.read_f32\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_f32\" class=\"fn\">read_f32</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.f32.html\">f32</a></h4></section></summary><div class='docblock'>Reads a 32 bit floating point number from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_f32\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.read_f64\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#124-126\">source</a><a href=\"#method.read_f64\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.read_f64\" class=\"fn\">read_f64</a>(self, buf: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>]) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.f64.html\">f64</a></h4></section></summary><div class='docblock'>Reads a 32 bit floating point number from <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.read_f64\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u16\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#134-141\">source</a><a href=\"#method.write_u16\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.write_u16\" class=\"fn\">write_u16</a>(self, buf: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>], n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u16.html\">u16</a>)</h4></section></summary><div class='docblock'>Writes an unsigned 16 bit integer <code>n</code> to <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.write_u16\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u32\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#149-156\">source</a><a href=\"#method.write_u32\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.write_u32\" class=\"fn\">write_u32</a>(self, buf: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>], n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u32.html\">u32</a>)</h4></section></summary><div class='docblock'>Writes an unsigned 32 bit integer <code>n</code> to <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.write_u32\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.write_u64\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#164-171\">source</a><a href=\"#method.write_u64\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"gimli/trait.Endianity.html#method.write_u64\" class=\"fn\">write_u64</a>(self, buf: &amp;mut [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u8.html\">u8</a>], n: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.u64.html\">u64</a>)</h4></section></summary><div class='docblock'>Writes an unsigned 64 bit integer <code>n</code> to <code>buf</code>. <a href=\"gimli/trait.Endianity.html#method.write_u64\">Read more</a></div></details></div></details>","Endianity","gimli::endianity::NativeEndian"],["<section id=\"impl-StructuralEq-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-StructuralEq-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.StructuralEq.html\" title=\"trait core::marker::StructuralEq\">StructuralEq</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section>","StructuralEq","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-Clone-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.75.0/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.75.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-Debug-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.75.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.75.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","gimli::endianity::NativeEndian"],["<section id=\"impl-Copy-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-Copy-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section>","Copy","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#208-213\">source</a><a href=\"#impl-Default-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#210-212\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.75.0/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","gimli::endianity::NativeEndian"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-PartialEq-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.75.0/src/core/cmp.rs.html#239\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.75.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.75.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","gimli::endianity::NativeEndian"],["<section id=\"impl-StructuralPartialEq-for-LittleEndian\" class=\"impl\"><a class=\"src rightside\" href=\"src/gimli/endianity.rs.html#205\">source</a><a href=\"#impl-StructuralPartialEq-for-LittleEndian\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.75.0/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"gimli/struct.LittleEndian.html\" title=\"struct gimli::LittleEndian\">LittleEndian</a></h3></section>","StructuralPartialEq","gimli::endianity::NativeEndian"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()