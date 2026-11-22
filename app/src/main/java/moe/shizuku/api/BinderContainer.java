package moe.shizuku.api;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;

/**
 * Minimal wire-compatible Parcelable wrapper for receiving the privileged Binder handle pushed by
 * the Shizuku server over ContentProvider IPC without external library dependencies.
 */
public final class BinderContainer implements Parcelable {

    public IBinder binder;

    public BinderContainer(IBinder binder) {
        this.binder = binder;
    }

    private BinderContainer(Parcel in) {
        this.binder = in.readStrongBinder();
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeStrongBinder(this.binder);
    }

    public static final Creator<BinderContainer> CREATOR = new Creator<BinderContainer>() {
        @Override
        public BinderContainer createFromParcel(Parcel source) {
            return new BinderContainer(source);
        }

        @Override
        public BinderContainer[] newArray(int size) {
            return new BinderContainer[size];
        }
    };
}
