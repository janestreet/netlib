@@ portable

(** Functions for working with and formatting 48-bit MAC addresses. *)

open Core

(** [private Int63.t] to enable immediate-type optimizations on 64-bit platforms. *)
type t = private Int63.t [@@deriving compare ~localize, sexp_grammar, typerep]

include%template Comparator.S [@modality portable] with type t := t

(** [of_string] and [t_of_sexp] accept any string-style notation (see [String_style]
    below). They accept both lowercase and uppercase hex digits. [to_string] and
    [sexp_of_t] use [Dash] style and lowercase hex digits. *)
include
  Identifiable.S_plain with type t := t and type comparator_witness := comparator_witness

include%template Sexplib0.Sexpable.Sexp_of [@alloc stack] with type t := t

include Quickcheckable with type t := t

(** More significant bytes in the integer go first in the address:
    {v
      0x112233445566 <-> 11-22-33-44-55-66
    v} *)
val of_int_exn : int -> t
[@@zero_alloc]

val to_int_exn : t -> int [@@zero_alloc]
val of_int63_exn : Int63.t -> t
val to_int63 : t -> Int63.t

module (String_style @@ nonportable) : sig @@ portable
  (** [Dash]-formatted strings look like "xx-xx-xx-xx-xx-xx", where the [x]'s are any hex
      digit. [Dot]-formatted strings look like "xxxx.xxxx.xxxx". [Colon]-formatted strings
      look like "xx:xx:xx:xx:xx:xx". [Compact] is "xxxxxxxxxxxx". *)
  type t =
    | Dash
    | Dot
    | Colon
    | Compact
  [@@deriving compare ~localize, sexp, enumerate]

  val arg : t Core.Command.Arg_type.t @@ nonportable

  module Stable : sig
    module V1 : Stable_without_comparator
    module V2 : Stable_without_comparator with type t = t
  end
end

(** [to_string_with_style] produces the dash-, colon-, or dot-separated string
    representation of the given MAC. It produces only lowercase hex digits. *)
val to_string_with_style : t -> style:String_style.t -> string

(** [to_string_colon] is an alias for: to_string_with_style ~style:Colon *)
val to_string_colon : t -> string

(** [to_string_compact] is an alias for: to_string_with_style ~style:Compact *)
val to_string_compact : t -> string

(** [to_string_dash] is an alias for: to_string_with_style ~style:Dash *)
val to_string_dash : t -> string

(** [to_string_dot] is an alias for: to_string_with_style ~style:Dot *)
val to_string_dot : t -> string

(** [broadcast] is ff-ff-ff-ff-ff-ff *)
val broadcast : t

(** [any] is 00-00-00-00-00-00 *)
val any : t

(** [random_incl ~state lo hi] returns a random [t] between [lo] (inclusive) and [hi]
    (inclusive). Raises if [lo > hi]. The comparison is such that the first byte in the
    address is the most significant, i.e. 00-00-00-00-00-01 < 01-00-00-00-00-00.

    The default [~state] is [Random.State.default]. *)
val random_incl : ?state:Random.State.t -> t -> t -> t

module Option : sig
  include Immediate_option.S_int63 with type value := t

  include%template Sexplib0.Sexpable.Sexp_of [@alloc stack] with type t := t

  include Equal.S with type t := t

  module Stable : sig
    module V2 : sig
      include Stable_comparable.V1 with type t = t

      include%template Sexplib0.Sexpable.Sexp_of [@alloc stack] with type t := t

      include Core.Core_stable.Hashable.V1.S with type key := t
    end
  end
end

(** [Unstable] provides (de)serializations that may change over time. In general, we
    suggest using [Stable], below, for (de)serializations. *)
module Unstable : sig
  include
    Identifiable.S_sexp_grammar
    with type t = t
     and type comparator_witness = comparator_witness

  include%template Sexplib0.Sexpable.Sexp_of [@alloc stack] with type t := t
end

module Stable : sig
  module V2 : sig
    type nonrec t = t [@@deriving sexp_grammar]

    include
      Stable_comparable.With_stable_witness.V1
      with type t := t
       and type comparator_witness = comparator_witness

    include Core.Core_stable.Hashable.V1.With_stable_witness.S with type key := t

    include%template Sexplib0.Sexpable.Sexp_of [@alloc stack] with type t := t
  end
end
