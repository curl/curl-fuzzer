import Long from "long";
import protobuf from "protobufjs";
import textformat from "protobufjs/ext/textformat.js";

protobuf.util.Long = Long;
protobuf.configure();
textformat.install();

globalThis.protobuf = protobuf;
