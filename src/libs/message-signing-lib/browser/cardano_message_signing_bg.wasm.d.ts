/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function __wbg_protectedheadermap_free(a: number): void;
export function protectedheadermap_to_bytes(a: number, b: number): void;
export function protectedheadermap_from_bytes(a: number, b: number, c: number): void;
export function protectedheadermap_new_empty(): number;
export function protectedheadermap_new(a: number): number;
export function protectedheadermap_deserialized_headers(a: number): number;
export function __wbg_label_free(a: number): void;
export function label_to_bytes(a: number, b: number): void;
export function label_from_bytes(a: number, b: number, c: number): void;
export function label_new_int(a: number): number;
export function label_new_text(a: number, b: number): number;
export function label_kind(a: number): number;
export function label_as_int(a: number): number;
export function label_as_text(a: number, b: number): void;
export function label_from_algorithm_id(a: number): number;
export function label_from_key_type(a: number): number;
export function label_from_ec_key(a: number): number;
export function label_from_curve_type(a: number): number;
export function label_from_key_operation(a: number): number;
export function __wbg_labels_free(a: number): void;
export function labels_to_bytes(a: number, b: number): void;
export function labels_from_bytes(a: number, b: number, c: number): void;
export function labels_len(a: number): number;
export function labels_get(a: number, b: number): number;
export function labels_add(a: number, b: number): void;
export function __wbg_cosesignatures_free(a: number): void;
export function cosesignatures_to_bytes(a: number, b: number): void;
export function cosesignatures_from_bytes(a: number, b: number, c: number): void;
export function cosesignatures_get(a: number, b: number): number;
export function cosesignatures_add(a: number, b: number): void;
export function countersignature_to_bytes(a: number, b: number): void;
export function countersignature_from_bytes(a: number, b: number, c: number): void;
export function countersignature_new_single(a: number): number;
export function countersignature_new_multi(a: number): number;
export function __wbg_headermap_free(a: number): void;
export function headermap_to_bytes(a: number, b: number): void;
export function headermap_from_bytes(a: number, b: number, c: number): void;
export function headermap_set_algorithm_id(a: number, b: number): void;
export function headermap_algorithm_id(a: number): number;
export function headermap_set_criticality(a: number, b: number): void;
export function headermap_criticality(a: number): number;
export function headermap_set_key_id(a: number, b: number, c: number): void;
export function headermap_key_id(a: number, b: number): void;
export function headermap_set_partial_init_vector(a: number, b: number, c: number): void;
export function headermap_partial_init_vector(a: number, b: number): void;
export function headermap_set_counter_signature(a: number, b: number): void;
export function headermap_counter_signature(a: number): number;
export function headermap_header(a: number, b: number): number;
export function headermap_set_header(a: number, b: number, c: number, d: number): void;
export function headermap_keys(a: number): number;
export function headermap_new(): number;
export function __wbg_headers_free(a: number): void;
export function headers_to_bytes(a: number, b: number): void;
export function headers_from_bytes(a: number, b: number, c: number): void;
export function headers_protected(a: number): number;
export function headers_unprotected(a: number): number;
export function headers_new(a: number, b: number): number;
export function __wbg_cosesignature_free(a: number): void;
export function cosesignature_to_bytes(a: number, b: number): void;
export function cosesignature_from_bytes(a: number, b: number, c: number): void;
export function cosesignature_new(a: number, b: number, c: number): number;
export function __wbg_cosesign1_free(a: number): void;
export function cosesign1_to_bytes(a: number, b: number): void;
export function cosesign1_from_bytes(a: number, b: number, c: number): void;
export function cosesign1_signature(a: number, b: number): void;
export function cosesign1_signed_data(a: number, b: number, c: number, d: number, e: number, f: number): void;
export function cosesign1_new(a: number, b: number, c: number, d: number, e: number): number;
export function __wbg_cosesign_free(a: number): void;
export function cosesign_to_bytes(a: number, b: number): void;
export function cosesign_from_bytes(a: number, b: number, c: number): void;
export function cosesign_signatures(a: number): number;
export function cosesign_new(a: number, b: number, c: number, d: number): number;
export function __wbg_signedmessage_free(a: number): void;
export function signedmessage_to_bytes(a: number, b: number): void;
export function signedmessage_from_bytes(a: number, b: number, c: number): void;
export function signedmessage_new_cose_sign(a: number): number;
export function signedmessage_new_cose_sign1(a: number): number;
export function signedmessage_from_user_facing_encoding(a: number, b: number, c: number): void;
export function signedmessage_to_user_facing_encoding(a: number, b: number): void;
export function signedmessage_kind(a: number): number;
export function signedmessage_as_cose_sign(a: number): number;
export function signedmessage_as_cose_sign1(a: number): number;
export function __wbg_sigstructure_free(a: number): void;
export function sigstructure_to_bytes(a: number, b: number): void;
export function sigstructure_from_bytes(a: number, b: number, c: number): void;
export function sigstructure_context(a: number): number;
export function sigstructure_body_protected(a: number): number;
export function sigstructure_sign_protected(a: number): number;
export function sigstructure_external_aad(a: number, b: number): void;
export function sigstructure_payload(a: number, b: number): void;
export function sigstructure_set_sign_protected(a: number, b: number): void;
export function sigstructure_new(a: number, b: number, c: number, d: number, e: number, f: number): number;
export function __wbg_coseencrypt0_free(a: number): void;
export function coseencrypt0_to_bytes(a: number, b: number): void;
export function coseencrypt0_from_bytes(a: number, b: number, c: number): void;
export function coseencrypt0_headers(a: number): number;
export function coseencrypt0_ciphertext(a: number, b: number): void;
export function coseencrypt0_new(a: number, b: number, c: number): number;
export function __wbg_passwordencryption_free(a: number): void;
export function passwordencryption_to_bytes(a: number, b: number): void;
export function passwordencryption_from_bytes(a: number, b: number, c: number): void;
export function passwordencryption_new(a: number): number;
export function __wbg_coserecipients_free(a: number): void;
export function coserecipients_to_bytes(a: number, b: number): void;
export function coserecipients_from_bytes(a: number, b: number, c: number): void;
export function coserecipients_new(): number;
export function coserecipients_len(a: number): number;
export function coserecipients_get(a: number, b: number): number;
export function coserecipients_add(a: number, b: number): void;
export function __wbg_coseencrypt_free(a: number): void;
export function coseencrypt_to_bytes(a: number, b: number): void;
export function coseencrypt_from_bytes(a: number, b: number, c: number): void;
export function coseencrypt_headers(a: number): number;
export function coseencrypt_ciphertext(a: number, b: number): void;
export function coseencrypt_recipients(a: number): number;
export function coseencrypt_new(a: number, b: number, c: number, d: number): number;
export function coserecipient_to_bytes(a: number, b: number): void;
export function coserecipient_from_bytes(a: number, b: number, c: number): void;
export function __wbg_pubkeyencryption_free(a: number): void;
export function pubkeyencryption_to_bytes(a: number, b: number): void;
export function pubkeyencryption_from_bytes(a: number, b: number, c: number): void;
export function pubkeyencryption_new(a: number): number;
export function __wbg_cosekey_free(a: number): void;
export function cosekey_to_bytes(a: number, b: number): void;
export function cosekey_from_bytes(a: number, b: number, c: number): void;
export function cosekey_set_key_type(a: number, b: number): void;
export function cosekey_key_type(a: number): number;
export function cosekey_set_key_id(a: number, b: number, c: number): void;
export function cosekey_key_id(a: number, b: number): void;
export function cosekey_set_algorithm_id(a: number, b: number): void;
export function cosekey_algorithm_id(a: number): number;
export function cosekey_set_key_ops(a: number, b: number): void;
export function cosekey_key_ops(a: number): number;
export function cosekey_set_base_init_vector(a: number, b: number, c: number): void;
export function cosekey_base_init_vector(a: number, b: number): void;
export function cosekey_header(a: number, b: number): number;
export function cosekey_set_header(a: number, b: number, c: number, d: number): void;
export function cosekey_new(a: number): number;
export function __wbg_coserecipient_free(a: number): void;
export function __wbg_countersignature_free(a: number): void;
export function headermap_set_init_vector(a: number, b: number, c: number): void;
export function cosesign_headers(a: number): number;
export function cosesignature_headers(a: number): number;
export function cosesign1_headers(a: number): number;
export function coserecipient_headers(a: number): number;
export function countersignature_signatures(a: number): number;
export function headermap_set_content_type(a: number, b: number): void;
export function labels_new(): number;
export function cosesignatures_new(): number;
export function coserecipient_new(a: number, b: number, c: number): number;
export function cosesignature_signature(a: number, b: number): void;
export function cosesign_payload(a: number, b: number): void;
export function cosesign1_payload(a: number, b: number): void;
export function coserecipient_ciphertext(a: number, b: number): void;
export function headermap_init_vector(a: number, b: number): void;
export function cosesignatures_len(a: number): number;
export function headermap_content_type(a: number): number;
export function __wbg_taggedcbor_free(a: number): void;
export function taggedcbor_to_bytes(a: number, b: number): void;
export function taggedcbor_from_bytes(a: number, b: number, c: number): void;
export function taggedcbor_tag(a: number): number;
export function taggedcbor_value(a: number): number;
export function taggedcbor_new(a: number, b: number): number;
export function __wbg_cborarray_free(a: number): void;
export function cborarray_to_bytes(a: number, b: number): void;
export function cborarray_from_bytes(a: number, b: number, c: number): void;
export function cborarray_new(): number;
export function cborarray_len(a: number): number;
export function cborarray_get(a: number, b: number): number;
export function cborarray_add(a: number, b: number): void;
export function cborarray_set_definite_encoding(a: number, b: number): void;
export function cborarray_is_definite(a: number): number;
export function __wbg_cborobject_free(a: number): void;
export function cborobject_to_bytes(a: number, b: number): void;
export function cborobject_from_bytes(a: number, b: number, c: number): void;
export function cborobject_new(): number;
export function cborobject_len(a: number): number;
export function cborobject_insert(a: number, b: number, c: number): number;
export function cborobject_get(a: number, b: number): number;
export function cborobject_keys(a: number): number;
export function cborobject_set_definite_encoding(a: number, b: number): void;
export function cborobject_is_definite(a: number): number;
export function __wbg_cborspecial_free(a: number): void;
export function cborspecial_to_bytes(a: number, b: number): void;
export function cborspecial_from_bytes(a: number, b: number, c: number): void;
export function cborspecial_new_bool(a: number): number;
export function cborspecial_new_unassigned(a: number): number;
export function cborspecial_new_break(): number;
export function cborspecial_new_null(): number;
export function cborspecial_new_undefined(): number;
export function cborspecial_kind(a: number): number;
export function cborspecial_as_bool(a: number): number;
export function cborspecial_as_float(a: number, b: number): void;
export function cborspecial_as_unassigned(a: number): number;
export function __wbg_cborvalue_free(a: number): void;
export function cborvalue_to_bytes(a: number, b: number): void;
export function cborvalue_from_bytes(a: number, b: number, c: number): void;
export function cborvalue_new_int(a: number): number;
export function cborvalue_new_bytes(a: number, b: number): number;
export function cborvalue_new_text(a: number, b: number): number;
export function cborvalue_new_array(a: number): number;
export function cborvalue_new_object(a: number): number;
export function cborvalue_new_tagged(a: number): number;
export function cborvalue_new_special(a: number): number;
export function cborvalue_from_label(a: number): number;
export function cborvalue_kind(a: number): number;
export function cborvalue_as_int(a: number): number;
export function cborvalue_as_bytes(a: number, b: number): void;
export function cborvalue_as_text(a: number, b: number): void;
export function cborvalue_as_array(a: number): number;
export function cborvalue_as_object(a: number): number;
export function cborvalue_as_tagged(a: number): number;
export function cborvalue_as_special(a: number): number;
export function __wbg_bignum_free(a: number): void;
export function bignum_to_bytes(a: number, b: number): void;
export function bignum_from_bytes(a: number, b: number, c: number): void;
export function bignum_from_str(a: number, b: number, c: number): void;
export function bignum_to_str(a: number, b: number): void;
export function bignum_checked_mul(a: number, b: number, c: number): void;
export function bignum_checked_add(a: number, b: number, c: number): void;
export function bignum_checked_sub(a: number, b: number, c: number): void;
export function __wbg_int_free(a: number): void;
export function int_new(a: number): number;
export function int_new_negative(a: number): number;
export function int_new_i32(a: number): number;
export function int_is_positive(a: number): number;
export function int_as_positive(a: number): number;
export function int_as_negative(a: number): number;
export function int_as_i32(a: number, b: number): void;
export function __wbg_cosesign1builder_free(a: number): void;
export function cosesign1builder_new(a: number, b: number, c: number, d: number): number;
export function cosesign1builder_hash_payload(a: number): void;
export function cosesign1builder_set_external_aad(a: number, b: number, c: number): void;
export function cosesign1builder_make_data_to_sign(a: number): number;
export function cosesign1builder_build(a: number, b: number, c: number): number;
export function cosesignbuilder_new(a: number, b: number, c: number, d: number): number;
export function cosesignbuilder_hash_payload(a: number): void;
export function cosesignbuilder_make_data_to_sign(a: number): number;
export function cosesignbuilder_build(a: number, b: number): number;
export function __wbg_eddsa25519key_free(a: number): void;
export function eddsa25519key_new(a: number, b: number): number;
export function eddsa25519key_set_private_key(a: number, b: number, c: number): void;
export function eddsa25519key_is_for_signing(a: number): void;
export function eddsa25519key_is_for_verifying(a: number): void;
export function eddsa25519key_build(a: number): number;
export function cosesignbuilder_set_external_aad(a: number, b: number, c: number): void;
export function __wbg_cosesignbuilder_free(a: number): void;
export function __wbindgen_malloc(a: number, b: number): number;
export function __wbindgen_realloc(a: number, b: number, c: number, d: number): number;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_free(a: number, b: number, c: number): void;
