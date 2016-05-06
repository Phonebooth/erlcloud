%% Amazon kms Service (kms)

-module(erlcloud_kms).

%%% Library initialization.
-export([configure/2, configure/3, configure/4,  new/2, new/3]).

-export([
         encrypt/2,encrypt/3,encrypt/4,encrypt/5,
         decrypt/1,decrypt/2,decrypt/3,decrypt/4,
         generate_data_key/2,generate_data_key/3,generate_data_key/4,generate_data_key/5,
         generate_data_key_without_plaintext/2,generate_data_key_without_plaintext/3,generate_data_key_without_plaintext/4,generate_data_key_without_plaintext/5
        ]).

-include_lib("erlcloud/include/erlcloud.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-spec new(string(), string()) -> aws_config().

new(AccessKeyID, SecretAccessKey) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey
      }.

-spec new(string(), string(), string()) -> aws_config().

new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey,
       kms_host=Host
      }.


-spec new(string(), string(), string(), non_neg_integer()) -> aws_config().

new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey,
       kms_host=Host,
       kms_port=Port
      }.

-spec configure(string(), string()) -> ok.

configure(AccessKeyID, SecretAccessKey) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey)),
    ok.

-spec configure(string(), string(), string()) -> ok.

configure(AccessKeyID, SecretAccessKey, Host) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host)),
    ok.

-spec configure(string(), string(), string(), non_neg_integer()) -> ok.

configure(AccessKeyID, SecretAccessKey, Host, Port) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host, Port)),
    ok.

default_config() -> erlcloud_aws:default_config().

%%------------------------------------------------------------------------------
%% @doc
%% KMS API:
%% [http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html]
%%
%% ===Example===
%%
%% Encrypts plaintext into ciphertext by using a customer master key.
%%
%% `
%% erlcloud_kms:encrypt(<<"dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>, <<"test">>).
%% {ok,[{<<"CiphertextBlob">>,
%%      <<"CiAM3x4grcEaPbMDWyM2obIf+PN9fSGIb97Fr5dYbjV7pRKLAQEBAgB4DN8eIK3BGj2zA1sjNqGyH/jzfX0hiG/exa+XWG41"...>>},
%%     {<<"KeyId">>,
%%      <<"arn:aws:kms:us-east-1:399517187155:key/dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------
-spec encrypt/2 :: (string(), string()) -> proplist().

encrypt(KeyId, Plaintext) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"Plaintext">>, base64:encode(Plaintext)}],
   erlcloud_kms_impl:request(default_config(), "TrentService.Encrypt", Json).

-spec encrypt/3 :: (string(), string(), string() | aws_config()) -> proplist().

encrypt(KeyId, Plaintext, Config) when is_record(Config, aws_config) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"Plaintext">>, Plaintext}],
   erlcloud_kms_impl:request(Config, "TrentService.Encrypt", Json);
encrypt(KeyId, Plaintext, ExplicitHashKey) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"Plaintext">>, Plaintext}, {<<"ExplicitHashKey">>, ExplicitHashKey}],
   erlcloud_kms_impl:request(default_config(), "TrentService.Encrypt", Json).

-spec encrypt/4 :: (proplist(), list(), string(), binary()) -> proplist().

encrypt(EncryptionContext, GrantTokens, KeyId, Plaintext) ->
   Json = [{<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeyId">>, KeyId}, {<<"Plaintext">>, Plaintext}],
   erlcloud_kms_impl:request(default_config(), "Encrypt", Json).

-spec encrypt/5 :: (proplist(), list(), string(), binary(), aws_config()) -> proplist().

encrypt(EncryptionContext, GrantTokens, KeyId, Plaintext, Config) when is_record(Config, aws_config) ->
   Json = [{<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeyId">>, KeyId}, {<<"Plaintext">>, Plaintext}],
   erlcloud_kms_impl:request(Config, "Encrypt", Json).

%%------------------------------------------------------------------------------
%% @doc
%% KMS API:
%% [http://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html]
%%
%% ===Example===
%%
%% Decrypts ciphertext.
%%
%% `
%%  {ok, [{_,_},{_,Base64}]} = erlcloud_kms:decrypt(<<"CiAM3x4grcEaPbMDWyM2obIf+PN9fSGIb97Fr5dYbjV7pRKLAQEBAgB4DN8eIK3BGj2zA1sjNqGyH/jzfX0hiG/exa+XWG41e6UAAABiMGAGCSqGSIb3DQEHBqBTMFECAQAwTAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwgXD+HP1C9QYNEI64CARCAHywvxWkct9cJwWCFO5mYUf2SZiWpXiY723+ayvlcUPY=">>).
%%       <<"arn:aws:kms:us-east-1:399517187155:key/dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>},
%%      {<<"Plaintext">>,<<"dGVzdA==">>}]}
%% 14> base64:decode(Base64).
%% <<"test">>
%% '
%%
%% @end
%%------------------------------------------------------------------------------
-spec decrypt/1 :: (string()) -> proplist().

decrypt(CiphertextBlob) ->
   Json = [{<<"CiphertextBlob">>, CiphertextBlob}],
   erlcloud_kms_impl:request(default_config(), "TrentService.Decrypt", Json).

-spec decrypt/2 :: (string(), string() | aws_config()) -> proplist().

decrypt(CiphertextBlob, Config) when is_record(Config, aws_config) ->
   Json = [{<<"CiphertextBlob">>, CiphertextBlob}],
   erlcloud_kms_impl:request(Config, "TrentService.Decrypt", Json);
decrypt(CiphertextBlob, ExplicitHashKey) ->
   Json = [{<<"CiphertextBlob">>, CiphertextBlob},{<<"ExplicitHashKey">>, ExplicitHashKey}],
   erlcloud_kms_impl:request(default_config(), "TrentService.Decrypt", Json).

-spec decrypt/3 :: (string(), proplist(), list()) -> proplist().

decrypt(CiphertextBlob, EncryptionContext, GrantTokens) ->
   Json = [{<<"CiphertextBlob">>, CiphertextBlob}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}],
   erlcloud_kms_impl:request(default_config(), "TrentService.Decrypt", Json).

-spec decrypt/4 :: (string(), proplist(), list(), aws_config() ) -> proplist().

decrypt(CiphertextBlob, EncryptionContext, GrantTokens, Config) when is_record(Config, aws_config) ->
   Json = [{<<"CiphertextBlob">>, CiphertextBlob}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}],
   erlcloud_kms_impl:request(Config, "TrentService.Decrypt", Json).

%%------------------------------------------------------------------------------
%% @doc
%% KMS API:
%% [http://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html]
%%
%%
%% ===Example===
%%
%% Generates a data key that you can use in your application to locally encrypt data. 
%%
%% erlcloud_kms:generate_data_key(<<"dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>,<<"AES_256">>).
%% {ok,[{<<"CiphertextBlob">>,
%%      <<"CiAM3x4grcEaPbMDWyM2obIf+PN9fSGIb97Fr5dYbjV7pRKnAQEBAwB4DN8eIK3BGj2zA1sjNqGyH/jzfX0hiG/exa+XWG41"...>>},
%%     {<<"KeyId">>,
%%      <<"arn:aws:kms:us-east-1:399517187155:key/dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>},
%%     {<<"Plaintext">>,
%%      <<"wpwtqGgs92XU3YSFdaAfxBOjd/6F2oM+bTfbDASrUiA=">>}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------
-spec generate_data_key/2 :: (string(), string()) -> proplist().

generate_data_key(KeyId, KeySpec) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKey", Json).

-spec generate_data_key/3 :: (string(), string(), string() | aws_config()) -> proplist().

generate_data_key(KeyId, KeySpec, Config) when is_record(Config, aws_config) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(Config, "TrentService.GenerateDataKey", Json);
generate_data_key(KeyId, KeySpec, ExplicitHashKey) ->
   Json = [{<<"KeyId">>, KeyId},{<<"KeySpec">>, KeySpec},{<<"ExplicitHashKey">>, ExplicitHashKey}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKey", Json).

-spec generate_data_key/4 :: (string(), proplist(), list(), string() ) -> proplist().

generate_data_key(KeyId, EncryptionContext, GrantTokens, KeySpec) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKey", Json).

-spec generate_data_key/5 :: (string(), proplist(), list(), string(), aws_config() ) -> proplist().

generate_data_key(KeyId, EncryptionContext, GrantTokens, KeySpec, Config) when is_record(Config, aws_config) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(Config, "TrentService.GenerateDataKey", Json).


%%------------------------------------------------------------------------------
%% @doc
%% KMS API:
%% [http://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html]
%%
%%
%% ===Example===
%%
%% Returns a data key encrypted by a customer master key without the plaintext copy of that key.
%%
%% erlcloud_kms:generate_data_key(<<"dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>,<<"AES_256">>).
%% {ok,[{<<"CiphertextBlob">>,
%%      <<"CiAM3x4grcEaPbMDWyM2obIf+PN9fSGIb97Fr5dYbjV7pRKnAQEBAwB4DN8eIK3BGj2zA1sjNqGyH/jzfX0hiG/exa+XWG41"...>>},
%%     {<<"KeyId">>,
%%      <<"arn:aws:kms:us-east-1:399517187155:key/dcbb9a7f-9e69-49e3-a9cf-babf71954f03">>},
%%     {<<"Plaintext">>,
%%      <<"wpwtqGgs92XU3YSFdaAfxBOjd/6F2oM+bTfbDASrUiA=">>}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------
-spec generate_data_key_without_plaintext/2 :: (string(), string()) -> proplist().

generate_data_key_without_plaintext(KeyId, KeySpec) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKeyWithoutPlaintext", Json).

-spec generate_data_key_without_plaintext/3 :: (string(), string(), string() | aws_config()) -> proplist().

generate_data_key_without_plaintext(KeyId, KeySpec, Config) when is_record(Config, aws_config) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(Config, "TrentService.GenerateDataKeyWithoutPlaintext", Json);
generate_data_key_without_plaintext(KeyId, KeySpec, ExplicitHashKey) ->
   Json = [{<<"KeyId">>, KeyId},{<<"KeySpec">>, KeySpec},{<<"ExplicitHashKey">>, ExplicitHashKey}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKeyWithoutPlaintext", Json).

-spec generate_data_key_without_plaintext/4 :: (string(), proplist(), list(), string() ) -> proplist().

generate_data_key_without_plaintext(KeyId, EncryptionContext, GrantTokens, KeySpec) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(default_config(), "TrentService.GenerateDataKeyWithoutPlaintext", Json).

-spec generate_data_key_without_plaintext/5 :: (string(), proplist(), list(), string(), aws_config() ) -> proplist().

generate_data_key_without_plaintext(KeyId, EncryptionContext, GrantTokens, KeySpec, Config) when is_record(Config, aws_config) ->
   Json = [{<<"KeyId">>, KeyId}, {<<"EncryptionContext">>, EncryptionContext}, {<<"GrantTokens">>, GrantTokens}, {<<"KeySpec">>, KeySpec}],
   erlcloud_kms_impl:request(Config, "TrentService.GenerateDataKeyWithoutPlaintext", Json).
