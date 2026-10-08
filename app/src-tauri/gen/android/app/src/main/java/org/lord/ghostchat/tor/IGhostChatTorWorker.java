package org.lord.ghostchat.tor;

import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/**
 * Small hand-written Binder contract. It replaces generated AIDL in this
 * generated Tauri scaffold while preserving a real cross-process interface.
 */
interface IGhostChatTorWorker extends IInterface {
    boolean start(Bundle launch) throws RemoteException;

    void stop() throws RemoteException;

    int getState() throws RemoteException;

    int getExitCode() throws RemoteException;

    int getUid() throws RemoteException;

    abstract class Stub extends Binder implements IGhostChatTorWorker {
        private static final String DESCRIPTOR =
                "org.lord.ghostchat.tor.IGhostChatTorWorker";
        private static final int TRANSACTION_START = IBinder.FIRST_CALL_TRANSACTION;
        private static final int TRANSACTION_STOP = IBinder.FIRST_CALL_TRANSACTION + 1;
        private static final int TRANSACTION_GET_STATE = IBinder.FIRST_CALL_TRANSACTION + 2;
        private static final int TRANSACTION_GET_EXIT_CODE = IBinder.FIRST_CALL_TRANSACTION + 3;
        private static final int TRANSACTION_GET_UID = IBinder.FIRST_CALL_TRANSACTION + 4;

        Stub() {
            attachInterface(this, DESCRIPTOR);
        }

        static IGhostChatTorWorker asInterface(IBinder binder) {
            IInterface local = binder.queryLocalInterface(DESCRIPTOR);
            if (local instanceof IGhostChatTorWorker) {
                return (IGhostChatTorWorker) local;
            }
            return new Proxy(binder);
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code == IBinder.INTERFACE_TRANSACTION) {
                reply.writeString(DESCRIPTOR);
                return true;
            }
            data.enforceInterface(DESCRIPTOR);
            switch (code) {
                case TRANSACTION_START:
                    Bundle launch = data.readBundle(getClass().getClassLoader());
                    reply.writeNoException();
                    reply.writeInt(start(launch) ? 1 : 0);
                    return true;
                case TRANSACTION_STOP:
                    stop();
                    reply.writeNoException();
                    return true;
                case TRANSACTION_GET_STATE:
                    reply.writeNoException();
                    reply.writeInt(getState());
                    return true;
                case TRANSACTION_GET_EXIT_CODE:
                    reply.writeNoException();
                    reply.writeInt(getExitCode());
                    return true;
                case TRANSACTION_GET_UID:
                    reply.writeNoException();
                    reply.writeInt(getUid());
                    return true;
                default:
                    return super.onTransact(code, data, reply, flags);
            }
        }

        private static final class Proxy implements IGhostChatTorWorker {
            private final IBinder remote;

            Proxy(IBinder remote) {
                this.remote = remote;
            }

            @Override
            public IBinder asBinder() {
                return remote;
            }

            @Override
            public boolean start(Bundle launch) throws RemoteException {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESCRIPTOR);
                    data.writeBundle(launch);
                    remote.transact(TRANSACTION_START, data, reply, 0);
                    reply.readException();
                    return reply.readInt() != 0;
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }

            @Override
            public void stop() throws RemoteException {
                transactVoid(TRANSACTION_STOP);
            }

            @Override
            public int getState() throws RemoteException {
                return transactInt(TRANSACTION_GET_STATE);
            }

            @Override
            public int getExitCode() throws RemoteException {
                return transactInt(TRANSACTION_GET_EXIT_CODE);
            }

            @Override
            public int getUid() throws RemoteException {
                return transactInt(TRANSACTION_GET_UID);
            }

            private void transactVoid(int code) throws RemoteException {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESCRIPTOR);
                    remote.transact(code, data, reply, 0);
                    reply.readException();
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }

            private int transactInt(int code) throws RemoteException {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(DESCRIPTOR);
                    remote.transact(code, data, reply, 0);
                    reply.readException();
                    return reply.readInt();
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }
        }
    }
}
