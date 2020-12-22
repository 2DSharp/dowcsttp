package me.twodee.dowcsttp.service;

import lombok.AllArgsConstructor;
import me.twodee.dowcsttp.ResultObject;
import me.twodee.dowcsttp.crypto.CryptoUtils;
import me.twodee.dowcsttp.crypto.PemFile;
import me.twodee.dowcsttp.model.dto.Pws;
import me.twodee.dowcsttp.model.entity.PwsIdentity;
import me.twodee.dowcsttp.repository.PwsIdentityRepository;

import java.io.IOException;

import static me.twodee.dowcsttp.Helper.generateUniqueId;
import static me.twodee.dowcsttp.crypto.CryptoUtils.generateSafeToken;

@AllArgsConstructor
public class Authorization {

    private PwsIdentityRepository repository;


    public ResultObject createNewPws(Pws.Registration data) throws IOException {
        if (repository.existsPwsIdentitiesByBaseUrlAndVerified(data.baseUrl, true)) {
            return ResultObject.builder().isSuccessful(false).error("An app with your base url already exists").build();
        }

        String challenge = generateSafeToken(256);
        String encrypted = CryptoUtils.encryptECIES(PemFile.readPublicKey(data.pubkey), challenge);

        PwsIdentity pws = PwsIdentity.builder()
                .baseUrl(data.baseUrl)
                .callback(data.callback)
                .description(data.description)
                .name(data.name)
                .id(generateUniqueId())
                .pubkey(data.pubkey)
                .verified(false)
                .build();

    }
}
