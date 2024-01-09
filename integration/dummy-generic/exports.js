(()=>{var e={641:(e,t,n)=>{const r=n(285);e.exports={AdmZip:r}},285:(e,t,n)=>{const r=n(173),o=n(17),i=n(396),a=n(333),s=(e,t)=>"boolean"==typeof e?e:t,c=(e,t)=>"string"==typeof e?e:t,f={noSort:!1,readEntries:!1,method:r.Constants.NONE,fs:null};e.exports=function(e,t){let n=null;const u=Object.assign(Object.create(null),f);e&&"object"==typeof e&&(e instanceof Uint8Array||(Object.assign(u,e),e=u.input?u.input:void 0,u.input&&delete u.input),Buffer.isBuffer(e)&&(n=e,u.method=r.Constants.BUFFER,e=void 0)),Object.assign(u,t);const l=new r(u);if(e&&"string"==typeof e){if(!l.fs.existsSync(e))throw new Error(r.Errors.INVALID_FILENAME);u.method=r.Constants.FILE,u.filename=e,n=l.fs.readFileSync(e)}const E=new a(n,u),{canonical:d,sanitize:h}=r;function I(e){var t;return e&&E&&("string"==typeof e&&(t=E.getEntry(e)),"object"==typeof e&&void 0!==e.entryName&&void 0!==e.header&&(t=E.getEntry(e.entryName)),t)?t:null}function m(e){const{join:t,normalize:n,sep:r}=o.posix;return t(".",n(r+e.split("\\").join(r)+r))}return{readFile:function(e,t){var n=I(e);return n&&n.getData(t)||null},readFileAsync:function(e,t){var n=I(e);n?n.getDataAsync(t):t(null,"getEntry failed for:"+e)},readAsText:function(e,t){var n=I(e);if(n){var r=n.getData();if(r&&r.length)return r.toString(t||"utf8")}return""},readAsTextAsync:function(e,t,n){var r=I(e);r?r.getDataAsync((function(e,r){r?t(e,r):e&&e.length?t(e.toString(n||"utf8")):t("")})):t("")},deleteFile:function(e){var t=I(e);t&&E.deleteEntry(t.entryName)},addZipComment:function(e){E.comment=e},getZipComment:function(){return E.comment||""},addZipEntryComment:function(e,t){var n=I(e);n&&(n.comment=t)},getZipEntryComment:function(e){var t=I(e);return t&&t.comment||""},updateFile:function(e,t){var n=I(e);n&&n.setData(t)},addLocalFile:function(e,t,n,o){if(!l.fs.existsSync(e))throw new Error(r.Errors.FILE_NOT_FOUND.replace("%s",e));{t=t?m(t):"";var i=e.split("\\").join("/").split("/").pop();t+=n||i;const r=l.fs.statSync(e);this.addFile(t,l.fs.readFileSync(e),o,r)}},addLocalFolder:function(e,t,n,i){var a;if(n instanceof RegExp?(a=n,n=function(e){return a.test(e)}):"function"!=typeof n&&(n=function(){return!0}),t=t?m(t):"",e=o.normalize(e),!l.fs.existsSync(e))throw new Error(r.Errors.FILE_NOT_FOUND.replace("%s",e));{const r=l.findFiles(e),a=this;r.length&&r.forEach((function(r){var s=o.relative(e,r).split("\\").join("/");if(n(s)){var c=l.fs.statSync(r);c.isFile()?a.addFile(t+s,l.fs.readFileSync(r),"",i||c):a.addFile(t+s+"/",Buffer.alloc(0),"",i||c)}}))}},addLocalFolderAsync:function(e,t,n,i){var a;i instanceof RegExp?(a=i,i=function(e){return a.test(e)}):"function"!=typeof i&&(i=function(){return!0}),n=n?m(n):"",e=o.normalize(e);var s=this;l.fs.open(e,"r",(function(a){if(a&&"ENOENT"===a.code)t(void 0,r.Errors.FILE_NOT_FOUND.replace("%s",e));else if(a)t(void 0,a);else{var c=l.findFiles(e),f=-1,u=function(){if((f+=1)<c.length){var r=c[f],a=o.relative(e,r).split("\\").join("/");a=a.normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/[^\x20-\x7E]/g,""),i(a)?l.fs.stat(r,(function(e,o){e&&t(void 0,e),o.isFile()?l.fs.readFile(r,(function(e,r){e?t(void 0,e):(s.addFile(n+a,r,"",o),u())})):(s.addFile(n+a+"/",Buffer.alloc(0),"",o),u())})):process.nextTick((()=>{u()}))}else t(!0,void 0)};u()}}))},addLocalFolderPromise:function(e,t){return new Promise(((n,r)=>{const{filter:o,zipPath:i}=Object.assign({},t);this.addLocalFolderAsync(e,((e,t)=>{t&&r(t),e&&n(this)}),i,o)}))},addFile:function(e,t,n,r){let o=I(e);const a=null!=o;a||(o=new i,o.entryName=e),o.comment=n||"";const s="object"==typeof r&&r instanceof l.fs.Stats;s&&(o.header.time=r.mtime);var c=o.isDirectory?16:0;let f=o.isDirectory?16384:32768;f|=s?4095&r.mode:"number"==typeof r?4095&r:o.isDirectory?493:420,c=(c|f<<16)>>>0,o.attr=c,o.setData(t),a||E.setEntry(o)},getEntries:function(){return E?E.entries:[]},getEntry:function(e){return I(e)},getEntryCount:function(){return E.getEntryCount()},forEach:function(e){return E.forEach(e)},extractEntryTo:function(e,t,n,i,a,f){i=s(i,!1),a=s(a,!1),n=s(n,!0),f=c(f,c(a,void 0));var u=I(e);if(!u)throw new Error(r.Errors.NO_ENTRY);var m=d(u.entryName),N=h(t,f&&!u.isDirectory?f:n?m:o.basename(m));if(u.isDirectory)return E.getEntryChildren(u).forEach((function(e){if(e.isDirectory)return;var s=e.getData();if(!s)throw new Error(r.Errors.CANT_EXTRACT_FILE);var c=d(e.entryName),f=h(t,n?c:o.basename(c));const u=a?e.header.fileAttr:void 0;l.writeFileTo(f,s,i,u)})),!0;var g=u.getData();if(!g)throw new Error(r.Errors.CANT_EXTRACT_FILE);if(l.fs.existsSync(N)&&!i)throw new Error(r.Errors.CANT_OVERRIDE);const y=a?e.header.fileAttr:void 0;return l.writeFileTo(N,g,i,y),!0},test:function(e){if(!E)return!1;for(var t in E.entries)try{if(t.isDirectory)continue;if(!E.entries[t].getData(e))return!1}catch(e){return!1}return!0},extractAllTo:function(e,t,n,o){if(t=s(t,!1),o=c(n,o),n=s(n,!1),!E)throw new Error(r.Errors.NO_ZIP);E.entries.forEach((function(i){var a=h(e,d(i.entryName.toString()));if(i.isDirectory)return void l.makeDir(a);var s=i.getData(o);if(!s)throw new Error(r.Errors.CANT_EXTRACT_FILE);const c=n?i.header.fileAttr:void 0;l.writeFileTo(a,s,t,c);try{l.fs.utimesSync(a,i.header.time,i.header.time)}catch(e){throw new Error(r.Errors.CANT_EXTRACT_FILE)}}))},extractAllToAsync:function(e,t,n,i){if(t=s(t,!1),"function"!=typeof n||i||(i=n),n=s(n,!1),i||(i=function(e){throw new Error(e)}),!E)return void i(new Error(r.Errors.NO_ZIP));e=o.resolve(e);const a=t=>h(e,o.normalize(d(t.entryName.toString()))),c=(e,t)=>new Error(e+': "'+t+'"'),f=[],u=new Set;E.entries.forEach((e=>{e.isDirectory?f.push(e):u.add(e)}));for(const e of f){const t=a(e),r=n?e.header.fileAttr:void 0;try{l.makeDir(t),r&&l.fs.chmodSync(t,r),l.fs.utimesSync(t,e.header.time,e.header.time)}catch(e){i(c("Unable to create folder",t))}}const I=()=>{0===u.size&&i()};for(const a of u.values()){const s=o.normalize(d(a.entryName.toString())),f=h(e,s);a.getDataAsync((function(e,o){if(o)i(new Error(o));else if(e){const r=n?a.header.fileAttr:void 0;l.writeFileToAsync(f,e,t,r,(function(e){e?l.fs.utimes(f,a.header.time,a.header.time,(function(e){e?i(c("Unable to set times",f)):(u.delete(a),I())})):i(c("Unable to write file",f))}))}else i(new Error(r.Errors.CANT_EXTRACT_FILE))}))}I()},writeZip:function(e,t){if(1===arguments.length&&"function"==typeof e&&(t=e,e=""),!e&&u.filename&&(e=u.filename),e){var n=E.compressToBuffer();if(n){var r=l.writeFileTo(e,n,!0);"function"==typeof t&&t(r?null:new Error("failed"),"")}}},writeZipPromise:function(e,t){const{overwrite:n,perm:r}=Object.assign({overwrite:!0},t);return new Promise(((t,o)=>{!e&&u.filename&&(e=u.filename),e||o("ADM-ZIP: ZIP File Name Missing"),this.toBufferPromise().then((i=>{l.writeFileToAsync(e,i,n,r,(e=>e?t(e):o("ADM-ZIP: Wasn't able to write zip file")))}),o)}))},toBufferPromise:function(){return new Promise(((e,t)=>{E.toAsyncBuffer(e,t)}))},toBuffer:function(e,t,n,r){return this.valueOf=2,"function"==typeof e?(E.toAsyncBuffer(e,t,n,r),null):E.compressToBuffer()}}}},907:(e,t,n)=>{var r=n(173),o=r.Constants;e.exports=function(){var e=20,t=10,n=0,i=0,a=0,s=0,c=0,f=0,u=0,l=0,E=0,d=0,h=0,I=0,m=0;e|=r.isWin?2560:768,n|=o.FLG_EFS;var N={};function g(e){e=new Date(e),a=(e.getFullYear()-1980&127)<<25|e.getMonth()+1<<21|e.getDate()<<16|e.getHours()<<11|e.getMinutes()<<5|e.getSeconds()>>1}return g(+new Date),{get made(){return e},set made(t){e=t},get version(){return t},set version(e){t=e},get flags(){return n},set flags(e){n=e},get method(){return i},set method(e){switch(e){case o.STORED:this.version=10;case o.DEFLATED:default:this.version=20}i=e},get time(){return new Date(1980+(a>>25&127),(a>>21&15)-1,a>>16&31,a>>11&31,a>>5&63,(31&a)<<1)},set time(e){g(e)},get crc(){return s},set crc(e){s=Math.max(0,e)>>>0},get compressedSize(){return c},set compressedSize(e){c=Math.max(0,e)>>>0},get size(){return f},set size(e){f=Math.max(0,e)>>>0},get fileNameLength(){return u},set fileNameLength(e){u=e},get extraLength(){return l},set extraLength(e){l=e},get commentLength(){return E},set commentLength(e){E=e},get diskNumStart(){return d},set diskNumStart(e){d=Math.max(0,e)>>>0},get inAttr(){return h},set inAttr(e){h=Math.max(0,e)>>>0},get attr(){return I},set attr(e){I=Math.max(0,e)>>>0},get fileAttr(){return I?(I>>>0|0)>>16&4095:0},get offset(){return m},set offset(e){m=Math.max(0,e)>>>0},get encripted(){return 1==(1&n)},get entryHeaderSize(){return o.CENHDR+u+l+E},get realDataOffset(){return m+o.LOCHDR+N.fnameLen+N.extraLen},get dataHeader(){return N},loadDataHeaderFromBinary:function(e){var t=e.slice(m,m+o.LOCHDR);if(t.readUInt32LE(0)!==o.LOCSIG)throw new Error(r.Errors.INVALID_LOC);N={version:t.readUInt16LE(o.LOCVER),flags:t.readUInt16LE(o.LOCFLG),method:t.readUInt16LE(o.LOCHOW),time:t.readUInt32LE(o.LOCTIM),crc:t.readUInt32LE(o.LOCCRC),compressedSize:t.readUInt32LE(o.LOCSIZ),size:t.readUInt32LE(o.LOCLEN),fnameLen:t.readUInt16LE(o.LOCNAM),extraLen:t.readUInt16LE(o.LOCEXT)}},loadFromBinary:function(N){if(N.length!==o.CENHDR||N.readUInt32LE(0)!==o.CENSIG)throw new Error(r.Errors.INVALID_CEN);e=N.readUInt16LE(o.CENVEM),t=N.readUInt16LE(o.CENVER),n=N.readUInt16LE(o.CENFLG),i=N.readUInt16LE(o.CENHOW),a=N.readUInt32LE(o.CENTIM),s=N.readUInt32LE(o.CENCRC),c=N.readUInt32LE(o.CENSIZ),f=N.readUInt32LE(o.CENLEN),u=N.readUInt16LE(o.CENNAM),l=N.readUInt16LE(o.CENEXT),E=N.readUInt16LE(o.CENCOM),d=N.readUInt16LE(o.CENDSK),h=N.readUInt16LE(o.CENATT),I=N.readUInt32LE(o.CENATX),m=N.readUInt32LE(o.CENOFF)},dataHeaderToBinary:function(){var e=Buffer.alloc(o.LOCHDR);return e.writeUInt32LE(o.LOCSIG,0),e.writeUInt16LE(t,o.LOCVER),e.writeUInt16LE(n,o.LOCFLG),e.writeUInt16LE(i,o.LOCHOW),e.writeUInt32LE(a,o.LOCTIM),e.writeUInt32LE(s,o.LOCCRC),e.writeUInt32LE(c,o.LOCSIZ),e.writeUInt32LE(f,o.LOCLEN),e.writeUInt16LE(u,o.LOCNAM),e.writeUInt16LE(l,o.LOCEXT),e},entryHeaderToBinary:function(){var r=Buffer.alloc(o.CENHDR+u+l+E);return r.writeUInt32LE(o.CENSIG,0),r.writeUInt16LE(e,o.CENVEM),r.writeUInt16LE(t,o.CENVER),r.writeUInt16LE(n,o.CENFLG),r.writeUInt16LE(i,o.CENHOW),r.writeUInt32LE(a,o.CENTIM),r.writeUInt32LE(s,o.CENCRC),r.writeUInt32LE(c,o.CENSIZ),r.writeUInt32LE(f,o.CENLEN),r.writeUInt16LE(u,o.CENNAM),r.writeUInt16LE(l,o.CENEXT),r.writeUInt16LE(E,o.CENCOM),r.writeUInt16LE(d,o.CENDSK),r.writeUInt16LE(h,o.CENATT),r.writeUInt32LE(I,o.CENATX),r.writeUInt32LE(m,o.CENOFF),r.fill(0,o.CENHDR),r},toJSON:function(){const a=function(e){return e+" bytes"};return{made:e,version:t,flags:n,method:r.methodToString(i),time:this.time,crc:"0x"+s.toString(16).toUpperCase(),compressedSize:a(c),size:a(f),fileNameLength:a(u),extraLength:a(l),commentLength:a(E),diskNumStart:d,inAttr:h,attr:I,offset:m,entryHeaderSize:a(o.CENHDR+u+l+E)}},toString:function(){return JSON.stringify(this.toJSON(),null,"\t")}}}},854:(e,t,n)=>{t.EntryHeader=n(907),t.MainHeader=n(519)},519:(e,t,n)=>{var r=n(173),o=r.Constants;e.exports=function(){var e=0,t=0,n=0,i=0,a=0;return{get diskEntries(){return e},set diskEntries(n){e=t=n},get totalEntries(){return t},set totalEntries(n){t=e=n},get size(){return n},set size(e){n=e},get offset(){return i},set offset(e){i=e},get commentLength(){return a},set commentLength(e){a=e},get mainHeaderSize(){return o.ENDHDR+a},loadFromBinary:function(s){if((s.length!==o.ENDHDR||s.readUInt32LE(0)!==o.ENDSIG)&&(s.length<o.ZIP64HDR||s.readUInt32LE(0)!==o.ZIP64SIG))throw new Error(r.Errors.INVALID_END);s.readUInt32LE(0)===o.ENDSIG?(e=s.readUInt16LE(o.ENDSUB),t=s.readUInt16LE(o.ENDTOT),n=s.readUInt32LE(o.ENDSIZ),i=s.readUInt32LE(o.ENDOFF),a=s.readUInt16LE(o.ENDCOM)):(e=r.readBigUInt64LE(s,o.ZIP64SUB),t=r.readBigUInt64LE(s,o.ZIP64TOT),n=r.readBigUInt64LE(s,o.ZIP64SIZE),i=r.readBigUInt64LE(s,o.ZIP64OFF),a=0)},toBinary:function(){var r=Buffer.alloc(o.ENDHDR+a);return r.writeUInt32LE(o.ENDSIG,0),r.writeUInt32LE(0,4),r.writeUInt16LE(e,o.ENDSUB),r.writeUInt16LE(t,o.ENDTOT),r.writeUInt32LE(n,o.ENDSIZ),r.writeUInt32LE(i,o.ENDOFF),r.writeUInt16LE(a,o.ENDCOM),r.fill(" ",o.ENDHDR),r},toJSON:function(){return{diskEntries:e,totalEntries:t,size:n+" bytes",offset:function(e,t){let n=e.toString(16).toUpperCase();for(;n.length<4;)n="0"+n;return"0x"+n}(i),commentLength:a}},toString:function(){return JSON.stringify(this.toJSON(),null,"\t")}}}},753:(e,t,n)=>{e.exports=function(e){var t=n(796),r={chunkSize:1024*(parseInt(e.length/1024)+1)};return{deflate:function(){return t.deflateRawSync(e,r)},deflateAsync:function(n){var o=t.createDeflateRaw(r),i=[],a=0;o.on("data",(function(e){i.push(e),a+=e.length})),o.on("end",(function(){var e=Buffer.alloc(a),t=0;e.fill(0);for(var r=0;r<i.length;r++){var o=i[r];o.copy(e,t),t+=o.length}n&&n(e)})),o.end(e)}}}},4:(e,t,n)=>{t.Deflater=n(753),t.Inflater=n(269),t.ZipCrypto=n(729)},269:(e,t,n)=>{e.exports=function(e){var t=n(796);return{inflate:function(){return t.inflateRawSync(e)},inflateAsync:function(n){var r=t.createInflateRaw(),o=[],i=0;r.on("data",(function(e){o.push(e),i+=e.length})),r.on("end",(function(){var e=Buffer.alloc(i),t=0;e.fill(0);for(var r=0;r<o.length;r++){var a=o[r];a.copy(e,t),t+=a.length}n&&n(e)})),r.end(e)}}}},729:(e,t,n)=>{"use strict";const{randomFillSync:r}=n(113),o=new Uint32Array(256).map(((e,t)=>{for(let e=0;e<8;e++)0!=(1&t)?t=t>>>1^3988292384:t>>>=1;return t>>>0})),i=(e,t)=>Math.imul(e,t)>>>0,a=(e,t)=>o[255&(e^t)]^e>>>8,s=()=>"function"==typeof r?r(Buffer.alloc(12)):s.node();s.node=()=>{const e=Buffer.alloc(12),t=e.length;for(let n=0;n<t;n++)e[n]=256*Math.random()&255;return e};const c={genSalt:s};function f(e){const t=Buffer.isBuffer(e)?e:Buffer.from(e);this.keys=new Uint32Array([305419896,591751049,878082192]);for(let e=0;e<t.length;e++)this.updateKeys(t[e])}f.prototype.updateKeys=function(e){const t=this.keys;return t[0]=a(t[0],e),t[1]+=255&t[0],t[1]=i(t[1],134775813)+1,t[2]=a(t[2],t[1]>>>24),e},f.prototype.next=function(){const e=(2|this.keys[2])>>>0;return i(e,1^e)>>8&255},e.exports={decrypt:function(e,t,n){if(!e||!Buffer.isBuffer(e)||e.length<12)return Buffer.alloc(0);const r=function(e){const t=new f(e);return function(e){const n=Buffer.alloc(e.length);let r=0;for(let o of e)n[r++]=t.updateKeys(o^t.next());return n}}(n);if(r(e.slice(0,12))[11]!==t.crc>>>24)throw"ADM-ZIP: Wrong Password";return r(e.slice(12))},encrypt:function(e,t,n,r=!1){null==e&&(e=Buffer.alloc(0)),Buffer.isBuffer(e)||(e=Buffer.from(e.toString()));const o=function(e){const t=new f(e);return function(e,n,r=0){n||(n=Buffer.alloc(e.length));for(let o of e){const e=t.next();n[r++]=o^e,t.updateKeys(o)}return n}}(n),i=c.genSalt();i[11]=t.crc>>>24&255,r&&(i[10]=t.crc>>>16&255);const a=Buffer.alloc(e.length+12);return o(i,a),o(e,a,12)},_salter:function(e){Buffer.isBuffer(e)&&e.length>=12?c.genSalt=function(){return e.slice(0,12)}:c.genSalt="node"===e?s.node:s}}},991:e=>{e.exports={LOCHDR:30,LOCSIG:67324752,LOCVER:4,LOCFLG:6,LOCHOW:8,LOCTIM:10,LOCCRC:14,LOCSIZ:18,LOCLEN:22,LOCNAM:26,LOCEXT:28,EXTSIG:134695760,EXTHDR:16,EXTCRC:4,EXTSIZ:8,EXTLEN:12,CENHDR:46,CENSIG:33639248,CENVEM:4,CENVER:6,CENFLG:8,CENHOW:10,CENTIM:12,CENCRC:16,CENSIZ:20,CENLEN:24,CENNAM:28,CENEXT:30,CENCOM:32,CENDSK:34,CENATT:36,CENATX:38,CENOFF:42,ENDHDR:22,ENDSIG:101010256,ENDSUB:8,ENDTOT:10,ENDSIZ:12,ENDOFF:16,ENDCOM:20,END64HDR:20,END64SIG:117853008,END64START:4,END64OFF:8,END64NUMDISKS:16,ZIP64SIG:101075792,ZIP64HDR:56,ZIP64LEAD:12,ZIP64SIZE:4,ZIP64VEM:12,ZIP64VER:14,ZIP64DSK:16,ZIP64DSKDIR:20,ZIP64SUB:24,ZIP64TOT:32,ZIP64SIZB:40,ZIP64OFF:48,ZIP64EXTRA:56,STORED:0,SHRUNK:1,REDUCED1:2,REDUCED2:3,REDUCED3:4,REDUCED4:5,IMPLODED:6,DEFLATED:8,ENHANCED_DEFLATED:9,PKWARE:10,BZIP2:12,LZMA:14,IBM_TERSE:18,IBM_LZ77:19,AES_ENCRYPT:99,FLG_ENC:1,FLG_COMP1:2,FLG_COMP2:4,FLG_DESC:8,FLG_ENH:16,FLG_PATCH:32,FLG_STR:64,FLG_EFS:2048,FLG_MSK:4096,FILE:2,BUFFER:1,NONE:0,EF_ID:0,EF_SIZE:2,ID_ZIP64:1,ID_AVINFO:7,ID_PFS:8,ID_OS2:9,ID_NTFS:10,ID_OPENVMS:12,ID_UNIX:13,ID_FORK:14,ID_PATCH:15,ID_X509_PKCS7:20,ID_X509_CERTID_F:21,ID_X509_CERTID_C:22,ID_STRONGENC:23,ID_RECORD_MGT:24,ID_X509_PKCS7_RL:25,ID_IBM1:101,ID_IBM2:102,ID_POSZIP:18064,EF_ZIP64_OR_32:4294967295,EF_ZIP64_OR_16:65535,EF_ZIP64_SUNCOMP:0,EF_ZIP64_SCOMP:8,EF_ZIP64_RHO:16,EF_ZIP64_DSN:24}},190:e=>{e.exports={INVALID_LOC:"Invalid LOC header (bad signature)",INVALID_CEN:"Invalid CEN header (bad signature)",INVALID_END:"Invalid END header (bad signature)",NO_DATA:"Nothing to decompress",BAD_CRC:"CRC32 checksum failed",FILE_IN_THE_WAY:"There is a file in the way: %s",UNKNOWN_METHOD:"Invalid/unsupported compression method",AVAIL_DATA:"inflate::Available inflate data did not terminate",INVALID_DISTANCE:"inflate::Invalid literal/length or distance code in fixed or dynamic block",TO_MANY_CODES:"inflate::Dynamic block code description: too many length or distance codes",INVALID_REPEAT_LEN:"inflate::Dynamic block code description: repeat more than specified lengths",INVALID_REPEAT_FIRST:"inflate::Dynamic block code description: repeat lengths with no first length",INCOMPLETE_CODES:"inflate::Dynamic block code description: code lengths codes incomplete",INVALID_DYN_DISTANCE:"inflate::Dynamic block code description: invalid distance code lengths",INVALID_CODES_LEN:"inflate::Dynamic block code description: invalid literal/length code lengths",INVALID_STORE_BLOCK:"inflate::Stored block length did not match one's complement",INVALID_BLOCK_TYPE:"inflate::Invalid block type (type == 3)",CANT_EXTRACT_FILE:"Could not extract the file",CANT_OVERRIDE:"Target file already exists",NO_ZIP:"No zip file was loaded",NO_ENTRY:"Entry doesn't exist",DIRECTORY_CONTENT_ERROR:"A directory cannot have content",FILE_NOT_FOUND:"File not found: %s",NOT_IMPLEMENTED:"Not implemented",INVALID_FILENAME:"Invalid filename",INVALID_FORMAT:"Invalid or unsupported zip format. No END header found"}},455:(e,t,n)=>{const r=n(147).require(),o=n(17);r.existsSync=r.existsSync||o.existsSync,e.exports=function(e){var t=e||"",n={directory:!1,readonly:!1,hidden:!1,executable:!1,mtime:0,atime:0},i=null;return t&&r.existsSync(t)?(i=r.statSync(t),n.directory=i.isDirectory(),n.mtime=i.mtime,n.atime=i.atime,n.executable=0!=(73&i.mode),n.readonly=0==(128&i.mode),n.hidden="."===o.basename(t)[0]):console.warn("Invalid path: "+t),{get directory(){return n.directory},get readOnly(){return n.readonly},get hidden(){return n.hidden},get mtime(){return n.mtime},get atime(){return n.atime},get executable(){return n.executable},decodeAttributes:function(){},encodeAttributes:function(){},toJSON:function(){return{path:t,isDirectory:n.directory,isReadOnly:n.readonly,isHidden:n.hidden,isExecutable:n.executable,mTime:n.mtime,aTime:n.atime}},toString:function(){return JSON.stringify(this.toJSON(),null,"\t")}}}},147:(e,t,n)=>{t.require=function(){if("object"==typeof process&&process.versions&&process.versions.electron)try{const e=n(Object(function(){var e=new Error("Cannot find module 'original-fs'");throw e.code="MODULE_NOT_FOUND",e}()));if(Object.keys(e).length>0)return e}catch(e){}return n(358)}},173:(e,t,n)=>{e.exports=n(646),e.exports.Constants=n(991),e.exports.Errors=n(190),e.exports.FileAttr=n(455)},646:(e,t,n)=>{const r=n(147).require(),o=n(17),i=n(991),a=n(190),s="object"==typeof process&&"win32"===process.platform,c=e=>e&&"object"==typeof e,f=new Uint32Array(256).map(((e,t)=>{for(let e=0;e<8;e++)0!=(1&t)?t=3988292384^t>>>1:t>>>=1;return t>>>0}));function u(e){this.sep=o.sep,this.fs=r,c(e)&&c(e.fs)&&"function"==typeof e.fs.statSync&&(this.fs=e.fs)}e.exports=u,u.prototype.makeDir=function(e){const t=this;!function(e){let n=e.split(t.sep)[0];e.split(t.sep).forEach((function(e){if(e&&":"!==e.substr(-1,1)){var r;n+=t.sep+e;try{r=t.fs.statSync(n)}catch(e){t.fs.mkdirSync(n)}if(r&&r.isFile())throw a.FILE_IN_THE_WAY.replace("%s",n)}}))}(e)},u.prototype.writeFileTo=function(e,t,n,r){const i=this;if(i.fs.existsSync(e)){if(!n)return!1;if(i.fs.statSync(e).isDirectory())return!1}var a,s=o.dirname(e);i.fs.existsSync(s)||i.makeDir(s);try{a=i.fs.openSync(e,"w",438)}catch(t){i.fs.chmodSync(e,438),a=i.fs.openSync(e,"w",438)}if(a)try{i.fs.writeSync(a,t,0,t.length,0)}finally{i.fs.closeSync(a)}return i.fs.chmodSync(e,r||438),!0},u.prototype.writeFileToAsync=function(e,t,n,r,i){"function"==typeof r&&(i=r,r=void 0);const a=this;a.fs.exists(e,(function(s){if(s&&!n)return i(!1);a.fs.stat(e,(function(n,c){if(s&&c.isDirectory())return i(!1);var f=o.dirname(e);a.fs.exists(f,(function(n){n||a.makeDir(f),a.fs.open(e,"w",438,(function(n,o){n?a.fs.chmod(e,438,(function(){a.fs.open(e,"w",438,(function(n,o){a.fs.write(o,t,0,t.length,0,(function(){a.fs.close(o,(function(){a.fs.chmod(e,r||438,(function(){i(!0)}))}))}))}))})):o?a.fs.write(o,t,0,t.length,0,(function(){a.fs.close(o,(function(){a.fs.chmod(e,r||438,(function(){i(!0)}))}))})):a.fs.chmod(e,r||438,(function(){i(!0)}))}))}))}))}))},u.prototype.findFiles=function(e){const t=this;return function e(n,r,i){"boolean"==typeof r&&(i=r,r=void 0);let a=[];return t.fs.readdirSync(n).forEach((function(s){var c=o.join(n,s);t.fs.statSync(c).isDirectory()&&i&&(a=a.concat(e(c,r,i))),r&&!r.test(c)||a.push(o.normalize(c)+(t.fs.statSync(c).isDirectory()?t.sep:""))})),a}(e,void 0,!0)},u.prototype.getAttributes=function(){},u.prototype.setAttributes=function(){},u.crc32update=function(e,t){return f[255&(e^t)]^e>>>8},u.crc32=function(e){"string"==typeof e&&(e=Buffer.from(e,"utf8")),f.length||genCRCTable();let t=e.length,n=-1;for(let r=0;r<t;)n=u.crc32update(n,e[r++]);return~n>>>0},u.methodToString=function(e){switch(e){case i.STORED:return"STORED ("+e+")";case i.DEFLATED:return"DEFLATED ("+e+")";default:return"UNSUPPORTED ("+e+")"}},u.canonical=function(e){if(!e)return"";var t=o.posix.normalize("/"+e.split("\\").join("/"));return o.join(".",t)},u.sanitize=function(e,t){e=o.resolve(o.normalize(e));for(var n=t.split("/"),r=0,i=n.length;r<i;r++){var a=o.normalize(o.join(e,n.slice(r,i).join(o.sep)));if(0===a.indexOf(e))return a}return o.normalize(o.join(e,o.basename(t)))},u.toBuffer=function(e){return Buffer.isBuffer(e)?e:e instanceof Uint8Array?Buffer.from(e):"string"==typeof e?Buffer.from(e,"utf8"):Buffer.alloc(0)},u.readBigUInt64LE=function(e,t){var n=Buffer.from(e.slice(t,t+8));return n.swap64(),parseInt(`0x${n.toString("hex")}`)},u.isWin=s,u.crcTable=f},396:(e,t,n)=>{var r=n(173),o=n(854),i=r.Constants,a=n(4);e.exports=function(e){var t=new o.EntryHeader,n=Buffer.alloc(0),s=Buffer.alloc(0),c=!1,f=null,u=Buffer.alloc(0);function l(){return e&&Buffer.isBuffer(e)?(t.loadDataHeaderFromBinary(e),e.slice(t.realDataOffset,t.realDataOffset+t.compressedSize)):Buffer.alloc(0)}function E(e){return 8==(8&t.flags)||r.crc32(e)===t.dataHeader.crc}function d(e,o,i){if(void 0===o&&"string"==typeof e&&(i=e,e=void 0),c)return e&&o&&o(Buffer.alloc(0),r.Errors.DIRECTORY_CONTENT_ERROR),Buffer.alloc(0);var s=l();if(0===s.length)return e&&o&&o(s),s;if(t.encripted){if("string"!=typeof i&&!Buffer.isBuffer(i))throw new Error("ADM-ZIP: Incompatible password parameter");s=a.ZipCrypto.decrypt(s,t,i)}var f=Buffer.alloc(t.size);switch(t.method){case r.Constants.STORED:if(s.copy(f),E(f))return e&&o&&o(f),f;throw e&&o&&o(f,r.Errors.BAD_CRC),new Error(r.Errors.BAD_CRC);case r.Constants.DEFLATED:var u=new a.Inflater(s);if(!e){if(u.inflate(f).copy(f,0),!E(f))throw new Error(r.Errors.BAD_CRC+" "+n.toString());return f}u.inflateAsync((function(e){e.copy(e,0),o&&(E(e)?o(e):o(e,r.Errors.BAD_CRC))}));break;default:throw e&&o&&o(Buffer.alloc(0),r.Errors.UNKNOWN_METHOD),new Error(r.Errors.UNKNOWN_METHOD)}}function h(n,o){if((!f||!f.length)&&Buffer.isBuffer(e))return n&&o&&o(l()),l();if(f.length&&!c){var i;switch(t.method){case r.Constants.STORED:return t.compressedSize=t.size,i=Buffer.alloc(f.length),f.copy(i),n&&o&&o(i),i;default:case r.Constants.DEFLATED:var s=new a.Deflater(f);if(!n){var u=s.deflate();return t.compressedSize=u.length,u}s.deflateAsync((function(e){i=Buffer.alloc(e.length),t.compressedSize=e.length,e.copy(i),o&&o(i)})),s=null}}else{if(!n||!o)return Buffer.alloc(0);o(Buffer.alloc(0))}}function I(e,t){return(e.readUInt32LE(t+4)<<4)+e.readUInt32LE(t)}function m(e){var n,r,o,a;e.length>=i.EF_ZIP64_SCOMP&&(n=I(e,i.EF_ZIP64_SUNCOMP),t.size===i.EF_ZIP64_OR_32&&(t.size=n)),e.length>=i.EF_ZIP64_RHO&&(r=I(e,i.EF_ZIP64_SCOMP),t.compressedSize===i.EF_ZIP64_OR_32&&(t.compressedSize=r)),e.length>=i.EF_ZIP64_DSN&&(o=I(e,i.EF_ZIP64_RHO),t.offset===i.EF_ZIP64_OR_32&&(t.offset=o)),e.length>=i.EF_ZIP64_DSN+4&&(a=e.readUInt32LE(i.EF_ZIP64_DSN),t.diskNumStart===i.EF_ZIP64_OR_16&&(t.diskNumStart=a))}return{get entryName(){return n.toString()},get rawEntryName(){return n},set entryName(e){var o=(n=r.toBuffer(e))[n.length-1];c=47===o||92===o,t.fileNameLength=n.length},get extra(){return u},set extra(e){u=e,t.extraLength=e.length,function(e){for(var t,n,r,o=0;o<e.length;)t=e.readUInt16LE(o),o+=2,n=e.readUInt16LE(o),o+=2,r=e.slice(o,o+n),o+=n,i.ID_ZIP64===t&&m(r)}(e)},get comment(){return s.toString()},set comment(e){s=r.toBuffer(e),t.commentLength=s.length},get name(){var e=n.toString();return c?e.substr(e.length-1).split("/").pop():e.split("/").pop()},get isDirectory(){return c},getCompressedData:function(){return h(!1,null)},getCompressedDataAsync:function(e){h(!0,e)},setData:function(e){f=r.toBuffer(e),!c&&f.length?(t.size=f.length,t.method=r.Constants.DEFLATED,t.crc=r.crc32(e),t.changed=!0):t.method=r.Constants.STORED},getData:function(e){return t.changed?f:d(!1,null,e)},getDataAsync:function(e,n){t.changed?e(f):d(!0,e,n)},set attr(e){t.attr=e},get attr(){return t.attr},set header(e){t.loadFromBinary(e)},get header(){return t},packHeader:function(){var e=t.entryHeaderToBinary(),o=r.Constants.CENHDR;return n.copy(e,o),o+=n.length,t.extraLength&&(u.copy(e,o),o+=t.extraLength),t.commentLength&&s.copy(e,o),e},toJSON:function(){const n=function(e){return"<"+(e&&e.length+" bytes buffer"||"null")+">"};return{entryName:this.entryName,name:this.name,comment:this.comment,isDirectory:this.isDirectory,header:t.toJSON(),compressedData:n(e),data:n(f)}},toString:function(){return JSON.stringify(this.toJSON(),null,"\t")}}}},333:(e,t,n)=>{const r=n(396),o=n(854),i=n(173);e.exports=function(e,t){var n=[],a={},s=Buffer.alloc(0),c=new o.MainHeader,f=!1;const u=Object.assign(Object.create(null),t),{noSort:l}=u;function E(){f=!0,a={},n=new Array(c.diskEntries);for(var t=c.offset,o=0;o<n.length;o++){var s=t,u=new r(e);u.header=e.slice(s,s+=i.Constants.CENHDR),u.entryName=e.slice(s,s+=u.header.fileNameLength),u.header.extraLength&&(u.extra=e.slice(s,s+=u.header.extraLength)),u.header.commentLength&&(u.comment=e.slice(s,s+u.header.commentLength)),t+=u.header.entryHeaderSize,n[o]=u,a[u.entryName]=u}}function d(){n.length>1&&!l&&n.sort(((e,t)=>e.entryName.toLowerCase().localeCompare(t.entryName.toLowerCase())))}return e?function(t){for(var n=e.length-i.Constants.ENDHDR,r=Math.max(0,n-65535),o=r,a=e.length,f=-1,u=0;n>=o;n--)if(80===e[n])if(e.readUInt32LE(n)!==i.Constants.ENDSIG)if(e.readUInt32LE(n)!==i.Constants.END64SIG){if(e.readUInt32LE(n)===i.Constants.ZIP64SIG){f=n,a=n+i.readBigUInt64LE(e,n+i.Constants.ZIP64SIZE)+i.Constants.ZIP64LEAD;break}}else o=r;else f=n,u=n,a=n+i.Constants.ENDHDR,o=n-i.Constants.END64HDR;if(!~f)throw new Error(i.Errors.INVALID_FORMAT);c.loadFromBinary(e.slice(f,a)),c.commentLength&&(s=e.slice(u+i.Constants.ENDHDR)),t&&E()}(u.readEntries):f=!0,{get entries(){return f||E(),n},get comment(){return s.toString()},set comment(e){s=i.toBuffer(e),c.commentLength=s.length},getEntryCount:function(){return f?n.length:c.diskEntries},forEach:function(t){f?n.forEach(t):function(t){const n=c.diskEntries;let o=c.offset;for(let a=0;a<n;a++){let n=o;const a=new r(e);a.header=e.slice(n,n+=i.Constants.CENHDR),a.entryName=e.slice(n,n+=a.header.fileNameLength),o+=a.header.entryHeaderSize,t(a)}}(t)},getEntry:function(e){return f||E(),a[e]||null},setEntry:function(e){f||E(),n.push(e),a[e.entryName]=e,c.totalEntries=n.length},deleteEntry:function(e){f||E();var t=a[e];if(t&&t.isDirectory){var r=this;this.getEntryChildren(t).forEach((function(t){t.entryName!==e&&r.deleteEntry(t.entryName)}))}n.splice(n.indexOf(t),1),delete a[e],c.totalEntries=n.length},getEntryChildren:function(e){if(f||E(),e&&e.isDirectory){const t=[],r=e.entryName,o=r.length;return n.forEach((function(e){e.entryName.substr(0,o)===r&&t.push(e)})),t}return[]},compressToBuffer:function(){f||E(),d();const e=[],t=[];let r=0,o=0;c.size=0,c.offset=0;for(const i of n){const n=i.getCompressedData();i.header.offset=o;const a=i.header.dataHeaderToBinary(),s=i.rawEntryName.length,f=Buffer.alloc(s+i.extra.length);i.rawEntryName.copy(f,0),f.copy(i.extra,s);const u=a.length+f.length+n.length;o+=u,e.push(a),e.push(f),e.push(n);const l=i.packHeader();t.push(l),c.size+=l.length,r+=u+l.length}r+=c.mainHeaderSize,c.offset=o,o=0;const a=Buffer.alloc(r);for(const t of e)t.copy(a,o),o+=t.length;for(const e of t)e.copy(a,o),o+=e.length;const u=c.toBinary();return s&&s.copy(u,i.Constants.ENDHDR),u.copy(a,o),a},toAsyncBuffer:function(e,t,r,o){try{f||E(),d();const t=[],a=[];let u=0,l=0;c.size=0,c.offset=0;const h=function(n){if(n.length){const e=n.pop(),i=e.entryName+e.extra.toString();r&&r(i),e.getCompressedDataAsync((function(r){o&&o(i),e.header.offset=l;const s=e.header.dataHeaderToBinary(),f=Buffer.alloc(i.length,i),E=s.length+f.length+r.length;l+=E,t.push(s),t.push(f),t.push(r);const d=e.packHeader();a.push(d),c.size+=d.length,u+=E+d.length,h(n)}))}else{u+=c.mainHeaderSize,c.offset=l,l=0;const n=Buffer.alloc(u);t.forEach((function(e){e.copy(n,l),l+=e.length})),a.forEach((function(e){e.copy(n,l),l+=e.length}));const r=c.toBinary();s&&s.copy(r,i.Constants.ENDHDR),r.copy(n,l),e(n)}};h(n)}catch(e){t(e)}}}}},113:e=>{"use strict";e.exports=require("crypto")},358:e=>{"use strict";e.exports=require("fs")},17:e=>{"use strict";e.exports=require("path")},796:e=>{"use strict";e.exports=require("zlib")}},t={};!function n(r){var o=t[r];if(void 0!==o)return o.exports;var i=t[r]={exports:{}};return e[r](i,i.exports,n),i.exports}(641)})();