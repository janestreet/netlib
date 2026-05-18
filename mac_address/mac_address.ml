open Core.Core_stable

module Stable = struct
  module String_style = struct
    module V1 = struct
      type t =
        | Dash
        | Dot
        | Colon
      [@@deriving bin_io, compare ~localize, enumerate, sexp, stable_witness]

      let%expect_test _ =
        print_endline [%bin_digest: t];
        [%expect {| edf14a38ecf9a1700217f3e6d9b483e4 |}]
      ;;
    end

    module V2 = struct
      type t =
        | Dash
        | Dot
        | Colon
        | Compact
      [@@deriving bin_io, compare ~localize, enumerate, sexp]

      let%expect_test _ =
        print_endline [%bin_digest: t];
        [%expect {| f0b53ec1ad2b8f571597f1fca7011c84 |}]
      ;;
    end

    module Latest = V2
  end

  module V2 = struct
    module Without_containers = struct
      type t = Int63.V1.t [@@deriving bin_io, compare ~localize, stable_witness]

      let%expect_test _ =
        print_endline [%bin_digest: t];
        [%expect {| 2b528f4b22f08e28876ffe0239315ac2 |}]
      ;;

      module Deriving_hash : sig @@ portable
          type t [@@deriving hash]
        end
        with type t := t = struct
        type t = Core.Int63.t [@@deriving hash]
      end

      include Deriving_hash

      let invalid_hex_char char =
        Core.raise_s [%message "invalid hex digit" (char : char)]
      ;;

      let invalid_hex_digit int = Core.raise_s [%message "invalid hex digit" (int : int)]

      (* convert a hex char to a int *)
      let int_of_hex c =
        match c with
        | '0' .. '9' -> int_of_char c - int_of_char '0'
        | 'a' .. 'f' -> int_of_char c - int_of_char 'a' + 10
        | 'A' .. 'F' -> int_of_char c - int_of_char 'A' + 10
        | _ -> invalid_hex_char c
      ;;

      (* convert a 4-bit number to a hex character *)
      let hex_of_int i =
        if i >= 0x0 && i <= 0x9
        then char_of_int (int_of_char '0' + i)
        else if i >= 0xa && i <= 0xf
        then char_of_int (int_of_char 'a' + (i - 0xa))
        else invalid_hex_digit i
      ;;

      let int63_of_int = Core.Int63.of_int
      let int_of_int63 = Core.Int63.to_int_exn
      let int63_of_hex c = int63_of_int (int_of_hex c)
      let hex_of_int63 int63 = hex_of_int (int_of_int63 int63)
      let bad_string s = Core.raise_s [%message "invalid MAC address" ~_:(s : string)]
      let get = Core.String.unsafe_get
      let set = Core.Bytes.unsafe_set

      include struct
        open Core.Int63

        let ( lxor ) = bit_xor
        let ( land ) = bit_and
        let ( lsl ) = shift_left
        let ( lsr ) = shift_right_logical
      end

      let of_string_compact s : t =
        (int63_of_hex (get s 0) lsl (4 * 11))
        lxor (int63_of_hex (get s 1) lsl (4 * 10))
        lxor (int63_of_hex (get s 2) lsl (4 * 9))
        lxor (int63_of_hex (get s 3) lsl (4 * 8))
        lxor (int63_of_hex (get s 4) lsl (4 * 7))
        lxor (int63_of_hex (get s 5) lsl (4 * 6))
        lxor (int63_of_hex (get s 6) lsl (4 * 5))
        lxor (int63_of_hex (get s 7) lsl (4 * 4))
        lxor (int63_of_hex (get s 8) lsl (4 * 3))
        lxor (int63_of_hex (get s 9) lsl (4 * 2))
        lxor (int63_of_hex (get s 10) lsl (4 * 1))
        lxor (int63_of_hex (get s 11) lsl (4 * 0))
      ;;

      let to_string_compact (t : t) =
        let s = Core.Bytes.create 12 in
        set s 0 (hex_of_int63 ((t lsr (4 * 11)) land int63_of_int 0xf));
        set s 1 (hex_of_int63 ((t lsr (4 * 10)) land int63_of_int 0xf));
        set s 2 (hex_of_int63 ((t lsr (4 * 9)) land int63_of_int 0xf));
        set s 3 (hex_of_int63 ((t lsr (4 * 8)) land int63_of_int 0xf));
        set s 4 (hex_of_int63 ((t lsr (4 * 7)) land int63_of_int 0xf));
        set s 5 (hex_of_int63 ((t lsr (4 * 6)) land int63_of_int 0xf));
        set s 6 (hex_of_int63 ((t lsr (4 * 5)) land int63_of_int 0xf));
        set s 7 (hex_of_int63 ((t lsr (4 * 4)) land int63_of_int 0xf));
        set s 8 (hex_of_int63 ((t lsr (4 * 3)) land int63_of_int 0xf));
        set s 9 (hex_of_int63 ((t lsr (4 * 2)) land int63_of_int 0xf));
        set s 10 (hex_of_int63 ((t lsr (4 * 1)) land int63_of_int 0xf));
        set s 11 (hex_of_int63 ((t lsr (4 * 0)) land int63_of_int 0xf));
        Core.Bytes.unsafe_to_string ~no_mutation_while_string_reachable:s
      ;;

      let of_string_quad s c : t =
        if (not (Core.Char.equal c (get s 4))) || not (Core.Char.equal c (get s 9))
        then bad_string s;
        (int63_of_hex (get s 0) lsl (4 * 11))
        lxor (int63_of_hex (get s 1) lsl (4 * 10))
        lxor (int63_of_hex (get s 2) lsl (4 * 9))
        lxor (int63_of_hex (get s 3) lsl (4 * 8))
        lxor (int63_of_hex (get s 5) lsl (4 * 7))
        lxor (int63_of_hex (get s 6) lsl (4 * 6))
        lxor (int63_of_hex (get s 7) lsl (4 * 5))
        lxor (int63_of_hex (get s 8) lsl (4 * 4))
        lxor (int63_of_hex (get s 10) lsl (4 * 3))
        lxor (int63_of_hex (get s 11) lsl (4 * 2))
        lxor (int63_of_hex (get s 12) lsl (4 * 1))
        lxor (int63_of_hex (get s 13) lsl (4 * 0))
      ;;

      let%template[@alloc a = (heap, stack)] to_string_quad (t : t) c =
        (let s = (Core.Bytes.make [@alloc a]) 14 c in
         set s 0 (hex_of_int63 ((t lsr (4 * 11)) land int63_of_int 0xf));
         set s 1 (hex_of_int63 ((t lsr (4 * 10)) land int63_of_int 0xf));
         set s 2 (hex_of_int63 ((t lsr (4 * 9)) land int63_of_int 0xf));
         set s 3 (hex_of_int63 ((t lsr (4 * 8)) land int63_of_int 0xf));
         set s 5 (hex_of_int63 ((t lsr (4 * 7)) land int63_of_int 0xf));
         set s 6 (hex_of_int63 ((t lsr (4 * 6)) land int63_of_int 0xf));
         set s 7 (hex_of_int63 ((t lsr (4 * 5)) land int63_of_int 0xf));
         set s 8 (hex_of_int63 ((t lsr (4 * 4)) land int63_of_int 0xf));
         set s 10 (hex_of_int63 ((t lsr (4 * 3)) land int63_of_int 0xf));
         set s 11 (hex_of_int63 ((t lsr (4 * 2)) land int63_of_int 0xf));
         set s 12 (hex_of_int63 ((t lsr (4 * 1)) land int63_of_int 0xf));
         set s 13 (hex_of_int63 ((t lsr (4 * 0)) land int63_of_int 0xf));
         Core.Bytes.unsafe_to_string ~no_mutation_while_string_reachable:s)
        [@exclave_if_stack a]
      ;;

      let of_string_pair s c : t =
        if (not (Core.Char.equal c (get s 2)))
           || (not (Core.Char.equal c (get s 5)))
           || (not (Core.Char.equal c (get s 8)))
           || (not (Core.Char.equal c (get s 11)))
           || not (Core.Char.equal c (get s 14))
        then bad_string s;
        (int63_of_hex (get s 0) lsl (4 * 11))
        lxor (int63_of_hex (get s 1) lsl (4 * 10))
        lxor (int63_of_hex (get s 3) lsl (4 * 9))
        lxor (int63_of_hex (get s 4) lsl (4 * 8))
        lxor (int63_of_hex (get s 6) lsl (4 * 7))
        lxor (int63_of_hex (get s 7) lsl (4 * 6))
        lxor (int63_of_hex (get s 9) lsl (4 * 5))
        lxor (int63_of_hex (get s 10) lsl (4 * 4))
        lxor (int63_of_hex (get s 12) lsl (4 * 3))
        lxor (int63_of_hex (get s 13) lsl (4 * 2))
        lxor (int63_of_hex (get s 15) lsl (4 * 1))
        lxor (int63_of_hex (get s 16) lsl (4 * 0))
      ;;

      let to_string_pair (t : t) c =
        let s = Core.Bytes.make 17 c in
        set s 0 (hex_of_int63 ((t lsr (4 * 11)) land int63_of_int 0xf));
        set s 1 (hex_of_int63 ((t lsr (4 * 10)) land int63_of_int 0xf));
        set s 3 (hex_of_int63 ((t lsr (4 * 9)) land int63_of_int 0xf));
        set s 4 (hex_of_int63 ((t lsr (4 * 8)) land int63_of_int 0xf));
        set s 6 (hex_of_int63 ((t lsr (4 * 7)) land int63_of_int 0xf));
        set s 7 (hex_of_int63 ((t lsr (4 * 6)) land int63_of_int 0xf));
        set s 9 (hex_of_int63 ((t lsr (4 * 5)) land int63_of_int 0xf));
        set s 10 (hex_of_int63 ((t lsr (4 * 4)) land int63_of_int 0xf));
        set s 12 (hex_of_int63 ((t lsr (4 * 3)) land int63_of_int 0xf));
        set s 13 (hex_of_int63 ((t lsr (4 * 2)) land int63_of_int 0xf));
        set s 15 (hex_of_int63 ((t lsr (4 * 1)) land int63_of_int 0xf));
        set s 16 (hex_of_int63 ((t lsr (4 * 0)) land int63_of_int 0xf));
        Core.Bytes.unsafe_to_string ~no_mutation_while_string_reachable:s
      ;;

      let of_string s : t =
        match Core.String.length s with
        | 12 -> of_string_compact s
        | 14 -> of_string_quad s '.'
        | 17 ->
          (match get s 2 with
           | ':' -> of_string_pair s ':'
           | '-' -> of_string_pair s '-'
           | _ -> bad_string s)
        | _ -> bad_string s
      ;;

      let%template[@alloc a = (heap, stack)] to_string_with_style (t : t) ~style =
        match[@exclave_if_stack a] (style : String_style.Latest.t) with
        | Dot -> (to_string_quad [@alloc a]) t '.'
        | Colon -> to_string_pair t ':'
        | Dash -> to_string_pair t '-'
        | Compact -> to_string_compact t
      ;;

      let%template[@alloc a = (heap, stack)] to_string (x : t) =
        (to_string_with_style [@alloc a]) x ~style:Dash [@exclave_if_stack a]
      ;;

      let to_string_colon (x : t) = to_string_with_style x ~style:Colon
      let to_string_compact (x : t) = to_string_with_style x ~style:Compact
      let to_string_dash (x : t) = to_string_with_style x ~style:Dash
      let to_string_dot (x : t) = to_string_with_style x ~style:Dot

      include%template
        Sexpable.Of_stringable.V1 [@modality portable] [@alloc stack] (struct
          type nonrec t = t

          let%template[@alloc a = (heap, stack)] to_string = (to_string [@alloc a])
          let of_string = of_string
        end)

      include%template Comparator.V1.Make [@modality portable] (struct
          type nonrec t = t [@@deriving compare ~localize, sexp_of]
        end)
    end

    include Without_containers

    include%template
      Comparable.V1.With_stable_witness.Make [@modality portable] (Without_containers)

    include%template
      Hashable.V1.With_stable_witness.Make [@modality portable] (Without_containers)

    include Unit_test (struct
        include Without_containers

        let%template equal a b = ([%compare.equal: t] [@mode local]) a b
        let make = Core.Int63.of_int64_exn

        let tests =
          [ make 0x0000_0000_0000L, "00-00-00-00-00-00", "\000"
          ; make 0x0123_4567_89abL, "01-23-45-67-89-ab", "\252\171\137gE#\001\000\000"
          ; make 0xfedc_ba98_7654L, "fe-dc-ba-98-76-54", "\252Tv\152\186\220\254\000\000"
          ; ( make 0xffff_ffff_ffffL
            , "ff-ff-ff-ff-ff-ff"
            , "\252\255\255\255\255\255\255\000\000" )
          ]
        ;;
      end)
  end

  module Option = struct
    module V2 = struct
      type t = Core.Int63.t [@@deriving bin_io, compare ~localize, hash]

      let%expect_test _ =
        print_endline [%bin_digest: t];
        [%expect {| 2b528f4b22f08e28876ffe0239315ac2 |}]
      ;;

      (* A [none] value of [Int63.min_value] is safe since any valid mac address will have
         the leading 2 bytes equal to 0. *)
      let none = Core.Int63.min_value
      let is_none t = Core.Int63.(t = none)
      let is_some t = not (is_none t)

      let some t =
        assert (is_some t);
        t
      ;;

      let some_is_representable = is_some
      let value_exn t = if is_some t then t else raise Stdlib.Not_found
      let value t ~default = Core.Bool.select (is_none t) default t
      let unchecked_value t = t

      let%template[@alloc a = (heap, stack)] to_option t =
        (if is_some t then Some (unchecked_value t) else None) [@exclave_if_stack a]
      ;;

      let of_option = function
        | None -> none
        | Some v -> some v
      ;;

      include%template
        Sexpable.Of_sexpable.V1 [@modality portable] [@alloc stack]
          (struct
            type t = V2.t option [@@deriving sexp ~stackify]
          end)
          (struct
            type nonrec t = t

            let%template[@alloc a = (heap, stack)] to_sexpable = (to_option [@alloc a])
            let of_sexpable = of_option
          end)

      include%template Comparator.V1.Make [@modality portable] (struct
          type nonrec t = t [@@deriving compare ~localize, sexp_of]
        end)

      include%template Hashable.V1.Make [@modality portable] (struct
          type nonrec t = t [@@deriving bin_io, compare ~localize, hash, sexp]
        end)

      include%template Comparable.V1.Make [@modality portable] (struct
          type nonrec t = t [@@deriving compare ~localize, sexp, bin_io]
          type nonrec comparator_witness = comparator_witness

          let comparator = comparator
        end)
    end
  end

  module Latest = V2
end

open Core
module Command = Core.Command

module String_style = struct
  module Stable = Stable.String_style
  include Stable.Latest
  include Sexpable.To_stringable (Stable.Latest)

  let arg =
    Command.Arg_type.of_alist_exn
      ~list_values_in_help:false
      (List.map all ~f:(fun t -> String.lowercase (to_string t), t))
  ;;
end

include Stable.Latest.Without_containers

let typerep_of_t = Int63.typerep_of_t
let typename_of_t = Int63.typename_of_t
let broadcast = Int63.of_int64_exn 0xffff_ffff_ffffL
let any = Int63.zero
let to_int63 = Fn.id

let[@cold] raise_invalid_mac mac_address =
  raise_s [%message "MAC address does not fit in 48 bits" (mac_address : Int63.Hex.t)]
;;

let%template[@inline] of_int63_exn mac_address =
  if not (([%compare.equal: t] [@mode local]) (mac_address land broadcast) mac_address)
  then raise_invalid_mac mac_address;
  mac_address
;;

let[@zero_alloc] of_int_exn int = of_int63_exn (Int63.of_int int)
let[@zero_alloc] to_int_exn t = Int63.to_int_exn (to_int63 t)
let quickcheck_generator = Int63.gen_incl any broadcast
let quickcheck_observer = Int63.quickcheck_observer
let quickcheck_shrinker = Int63.quickcheck_shrinker

module Unstable = struct
  include%template Identifiable.Make_using_comparator [@modality portable] (struct
      include Stable.Latest

      let module_name = "Mac_address"
    end)

  include Stable.Latest.Without_containers
end

include Unstable

let random_incl ?state lo hi =
  Int63.random_incl ?state (to_int63 lo) (to_int63 hi) |> of_int63_exn
;;

(* Restore the direct comparisons shadowed by [Comparable] *)
include Int63.Replace_polymorphic_compare

module Option = struct
  module Stable = Stable.Option

  module T = struct
    include Stable.V2

    [%%rederive type t = Int63.t [@@deriving typerep]]

    include%template Sexpable.To_stringable [@modality portable] (Stable.V2)

    module Optional_syntax = struct
      module Optional_syntax = struct
        let is_none = is_none
        let unsafe_value = unchecked_value
      end
    end
  end

  include T

  (* Restore the direct comparisons shadowed by [Comparable] *)
  include Int63.Replace_polymorphic_compare
end
