package org.xacml4j.opensaml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2014 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;

public class KeyStoreFactory implements FactoryBean<KeyStore> {

	private String ksType;
	private Resource ksLocation;
	private String ksPassword;

	@Override
	public KeyStore getObject() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(ksType);
		ks.load(ksLocation.getInputStream(), ksPassword.toCharArray());
		return ks;
	}

	@Override
	public Class<?> getObjectType() {
		return KeyStore.class;
	}

	@Override
	public boolean isSingleton() {
		return false;
	}

	public void setType(String type) {
		this.ksType = type;
	}

	public void setLocation(Resource location) {
		this.ksLocation = location;
	}

	public void setPassword(String password) {
		this.ksPassword = password;
	}
}
