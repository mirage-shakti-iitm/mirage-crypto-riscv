let std_flags = ["--std=c99"; "-Wall"; "-Wextra"; "-Wpedantic"; "-I/home/sai/.opam/4.11.1+riscv/riscv-sysroot/include/ocaml-boot-riscv"] 
(* Removed -O3 flag *)

let _ =
  let c = Configurator.V1.create "mirage-crypto" in
  let arch =
    let arch = Configurator.V1.Process.run c "uname" ["-m"] in
    String.trim arch.Configurator.V1.Process.stdout
  in
  let accelerate_flags =
    match arch with
    (* | "x86_64" | "amd64" -> [ "-DACCELERATE"; "-mssse3"; "-maes"; "-mpclmul" ] *)
    | _ -> []
  in
  let ent_flags =
    match arch with
    (* | "x86_64" | "amd64" | "x86" -> [ "-DENTROPY"; "-mrdrnd"; "-mrdseed" ] *)
    | _ -> ["-DENTROPY"]
  in
  let fs = std_flags @ ent_flags @ accelerate_flags in
  Format.(printf "(@[%a@])@.%!" (fun ppf -> List.iter (fprintf ppf "%s@ ")) fs)
